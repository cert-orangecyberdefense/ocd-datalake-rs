extern crate core;

pub mod setting;
pub mod error;
pub mod bulk_search;

use std::collections::{BTreeMap, HashMap};
use std::thread;
use std::time::{Duration, Instant};
use log::{info, debug};
use std::env;
use reqwest::Proxy;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::AUTHORIZATION;
use serde_json::{json, Map, Value};
use crate::bulk_search::{create_bulk_search_task, download_bulk_search, get_bulk_search_task, State};
use crate::error::{DatalakeError, DetailedError};
use crate::DatalakeError::{ApiError, AuthenticationError, TimeoutError, ProxyError, UnexpectedLibError};
pub use crate::setting::{DatalakeSetting, RoutesSetting};

pub const ATOM_VALUE_QUERY_FIELD: &str = "atom_value";

#[derive(Clone, Debug)]
struct Tokens {  // Tokens are saved with the "Token " prefix
    access: String,
    refresh: String,
}

#[derive(Clone, Debug)]
pub struct Datalake {
    settings: DatalakeSetting,
    username: String,
    password: String,
    client: Client,
    tokens: Option<Tokens>,
}

fn build_client() -> Result<Client, DatalakeError> {
    let https_proxy = env::var("HTTPS_PROXY").ok();
    let http_proxy = env::var("HTTP_PROXY").ok();
    let client_builder = Client::builder();
    
    // Try HTTPS_PROXY first, then HTTP_PROXY, otherwise use default client
    if let Some(url) = https_proxy.or(http_proxy) {
        debug!("{}", format!("Using Proxy : {url}"));
        if url.starts_with("http") {
            match Proxy::all(&url) {
                Ok(proxy) => client_builder
                    .proxy(proxy)
                    .build()
                    .map_err(|e| ProxyError(DetailedError::new(format!("Failed to build client : {e}")))),
                Err(e) => Err(ProxyError(DetailedError::new(format!("Invalid proxy URL : {e}"))))
            }
        } else {
            Err(ProxyError(DetailedError::new(format!("Invalid proxy URL : {url}"))))
        }
    } else {
        debug!("No proxies configured, using default client. To specify a proxy, please set the HTTP_PROXY(S) env variable.");
        Ok(Client::new())
    }
}

impl Datalake {
    pub fn new(username: String, password: String, settings: DatalakeSetting) -> Self {
        let client = match build_client() {
            Ok(client) => client,
            Err(err) => {
                panic!("Failed to build client: {err}")
            }
        };
        Datalake {
            settings,
            username,
            password,
            client,
            tokens: None,
        }
    }

    fn retrieve_api_tokens(&self) -> Result<Tokens, DatalakeError> {
        let url = &self.settings.routes().authentication;
        let auth_request = self.client.post(url);
        let mut json_body = HashMap::new();
        json_body.insert("email", &self.username);
        json_body.insert("password", &self.password);
        let resp = auth_request.json(&json_body).send()?;
        let status_code = resp.status();
        let json_resp = resp.json::<Value>()?;
        let raw_access_token = json_resp["access_token"].as_str();
        let raw_refresh_token = json_resp["refresh_token"].as_str();
        if raw_access_token.is_none() || raw_refresh_token.is_none() {
            let err = DetailedError {
                summary: "Invalid credentials".to_string(),
                api_url: Some(url.to_string()),
                api_response: Some(json_resp.to_string()),
                api_status_code: Some(status_code),
            };
            return Err(AuthenticationError(err));
        }  // Else access and refresh token are guaranteed to be there
        let access_token = format!("Token {}", raw_access_token.unwrap());
        let refresh_token = format!("Token {}", raw_refresh_token.unwrap());

        Ok(Tokens {
            access: access_token,
            refresh: refresh_token,
        })
    }

    /// Cached version of retrieve_api_token that return a new token only if needed
    pub fn get_access_token(&mut self) -> Result<String, DatalakeError> {
        if self.tokens.is_none() {
            self.tokens = Some(self.retrieve_api_tokens()?);
        }
        let access_token = self.tokens.as_ref().unwrap().clone().access;
        Ok(access_token)
    }

    /// Return valid tokens, first by using the refresh token, then by using user credentials
    fn refresh_tokens(&self) -> Result<Tokens, DatalakeError> {
        info!("Refreshing the access token");
        let url = &self.settings.routes().refresh_token;
        let refresh_token = if let Some(tokens) = &self.tokens {
            tokens.clone().refresh
        } else {
            let error_message = "Refresh tokens called despite no token set".to_string();
            return Err(UnexpectedLibError(DetailedError::new(error_message)));
        };
        let request = self.client.post(url)
            .header("Authorization", refresh_token.clone());

        let resp = request.send()?;
        let status_code = resp.status();
        if status_code == 401 {
            info!("Refresh token is expired, authenticating from the start");
            return self.retrieve_api_tokens();
        }
        let json_resp = resp.json::<Value>()?;
        let access_token = match json_resp["access_token"].as_str() {
            None => {
                let err = DetailedError {
                    summary: "Invalid credentials".to_string(),
                    api_url: Some(url.to_string()),
                    api_response: Some(json_resp.to_string()),
                    api_status_code: Some(status_code),
                };
                return Err(AuthenticationError(err));
            }
            Some(raw_access_token) => format!("Token {}", raw_access_token)
        };

        Ok(Tokens {
            access: access_token,
            refresh: refresh_token,
        })
    }

    /// Return the atom types based on the given atom_values
    pub fn extract_atom_type(&mut self, atom_values: &[String]) -> Result<BTreeMap<String, String>, DatalakeError> {
        let url = self.settings.routes().atom_values_extract.clone();
        let mut request = self.client.post(&url);
        let mut joined_atom_values = String::from(&atom_values[0]);
        for value in atom_values.iter().skip(1) {
            joined_atom_values.push(' ');
            joined_atom_values.push_str(value);
        }
        let json_body = json!({
            "content": joined_atom_values,
        });
        request = request.json(&json_body);
        let resp = self.run_with_authorization_token(&request)?;
        let status_code = resp.status();
        let json_resp = resp.json::<Value>()?;
        let extracted_atom_types = Self::parse_extract_atom_type_result(&json_resp);
        if let Some(extracted) = extracted_atom_types {
            Ok(extracted)
        } else {
            let err = DetailedError {
                summary: "extracted API response not as expected".to_string(),
                api_url: Some(url),
                api_response: Some(json_resp.to_string()),
                api_status_code: Some(status_code),
            };
            Err(ApiError(err))
        }
    }

    /// Run a request by injecting authorization token. Automatically retry once if the token is expired
    fn run_with_authorization_token(&mut self, request: &RequestBuilder) -> Result<Response, DatalakeError> {
        let Some(mut cloned_request) = request.try_clone() else {
            return Err(UnexpectedLibError(DetailedError::new("Can't clone given request".to_string())))
        };
        cloned_request = cloned_request.header(AUTHORIZATION, self.get_access_token()?);
        let mut response = cloned_request.send()?;
        let mut status_code = response.status();
        if status_code != 401 {
            return Ok(response);
        }

        // Else retry
        self.tokens = Some(self.refresh_tokens()?);
        let refreshed_token = self.get_access_token()?;
        let Some(mut retry_request) = request.try_clone() else {
            return Err(UnexpectedLibError(DetailedError::new("Can't clone given request".to_string())))
        };
        retry_request = retry_request.header(AUTHORIZATION, refreshed_token);
        response = retry_request.send()?;
        status_code = response.status();
        if status_code == 401 {
            Err(AuthenticationError(DetailedError {
                summary: "401 response despite refreshed token".to_string(),
                api_url: Some(response.url().to_string()),
                api_response: response.text().ok(),
                api_status_code: Some(status_code),
            }))
        } else {
            Ok(response)  // Refreshing the token was enough to yield a correct response
        }
    }

    fn parse_extract_atom_type_result(json_resp: &Value) -> Option<BTreeMap<String, String>> {
        let results_value = json_resp.get("results")?;
        let results = results_value.as_object()?;
        let mut extracted_atom_types = BTreeMap::new();
        for (atom_type, atoms) in results {
            for atom in atoms.as_array()? {
                let atom_value = atom.as_str()?.to_string();
                extracted_atom_types.insert(atom_value, atom_type.clone());
            }
        }
        Some(extracted_atom_types)
    }

    /// Return a CSV of the bulk lookup for given threats
    ///
    /// Threats have their atom type automatically defined (with hash meaning a File type)
    pub fn bulk_lookup(&mut self, atom_values: Vec<String>) -> Result<String, DatalakeError> {
        let mut csv_merged = String::new();
        for chunk in atom_values.chunks(self.settings.bulk_lookup_chunk_size) {
            let csv: String = self.bulk_lookup_chunk(chunk)?;
            if csv_merged.is_empty() {
                csv_merged = csv;
            } else {
                let body = match csv.split_once('\n') {
                    Some((_header, body)) => body,
                    None => return Err(Self::csv_without_new_line_error(csv)),
                };
                csv_merged = format!("{csv_merged}{body}");
            }
            if !csv_merged.ends_with('\n') {
                csv_merged.push('\n');  // It's easier to merge csv if they always finish with a new line
            }
        }
        Ok(csv_merged)
    }

    fn csv_without_new_line_error(csv: String) -> DatalakeError {
        let detailed_error = DetailedError {
            summary: "unexpected csv result, missing body".to_string(),
            api_url: None,
            api_response: Some(csv),
            api_status_code: None,
        };
        ApiError(detailed_error)
    }

    /// Bulk lookup a chunk of atom_values
    fn bulk_lookup_chunk(&mut self, atom_values: &[String]) -> Result<String, DatalakeError> {
        // Construct the body by identifying the atom types
        let extracted = self.extract_atom_type(atom_values)?;
        let mut body = Map::new();
        body.insert("hashkey_only".to_string(), Value::Bool(false));
        for (atom_value, atom_type) in extracted {
            let value_to_insert = Value::String(atom_value);
            let entry: Option<&mut Value> = body.get_mut(atom_type.as_str());
            if let Some(atom_value_array) = entry {
                // Add the atom value to an already existing array
                atom_value_array.as_array_mut().unwrap().push(value_to_insert);
            } else {
                let new_array = Value::Array(vec![value_to_insert]);
                body.insert(atom_type, new_array);
            };
        }

        let request = self.client.post(&self.settings.routes().bulk_lookup)
            .header("Accept", "text/csv")
            .json(&body);
        let csv_resp = self.run_with_authorization_token(&request)?.text()?;
        Ok(csv_resp)
    }

    /// Retrieve all the results of a query using its query_hash.
    ///
    /// Fields returned depend on query_fields.
    /// For now the result is returned as a CSV.
    /// > **Warning** the function is blocking while the bulk search is being processed by the API (up to 1h)
    pub fn bulk_search(&mut self, query_hash: String, query_fields: Vec<String>) -> Result<String, DatalakeError> {
        let task_uuid = create_bulk_search_task(self, query_hash, query_fields)?;
        let timeout = self.settings.bulk_search_timeout_sec;
        let start_time = Instant::now();
        let mut bulk_search_is_ready = false;
        while !bulk_search_is_ready {
            if start_time.elapsed().as_secs() > timeout {
                let error_summary = format!("Bulk search is not finished after {timeout} seconds");
                return Err(TimeoutError(DetailedError::new(error_summary)));
            }
            thread::sleep(Duration::from_secs(self.settings.bulk_search_retry_interval_sec));
            let task = get_bulk_search_task(self, task_uuid.clone())?;
            let state = task.get_state()?;
            bulk_search_is_ready = match state {
                State::DONE => true,
                State::NEW | State::QUEUED | State::IN_PROGRESS => false,  // bulk search is not ready yet
                State::CANCELLED | State::FAILED_ERROR | State::FAILED_TIMEOUT => {
                    return Err(ApiError(DetailedError::new(format!("Bulk search ended with {state} state"))));
                }
            }
        }
        download_bulk_search(self, task_uuid)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Datalake, DatalakeSetting};
    use crate::error::DatalakeError::UnexpectedLibError;
    use crate::error::DetailedError;
    use crate::build_client;
    use std::env;

    #[test]
    fn test_proxy_client_creation() {
        env::remove_var("HTTP_PROXY");
        env::remove_var("HTTPS_PROXY");
        let result = build_client();
        assert!(result.is_ok(), "Should build client with no proxy");
        
        env::set_var("HTTPS_PROXY", "https://example-proxy-1.com:8080");
        let result = build_client();
        assert!(result.is_ok(), "Should build client with valid HTTP proxy");
        
        env::remove_var("HTTPS_PROXY");
        env::set_var("HTTP_PROXY", "http://example-proxy-2.com:8080");
        let result = build_client();
        assert!(result.is_ok(), "Should build client with valid HTTP proxy");
        
        env::set_var("HTTP_PROXY", "invalid-url");
        let result = build_client();
        assert!(result.is_err(), "Should fail with invalid proxy URL");
        
        env::remove_var("HTTP_PROXY");
        env::remove_var("HTTPS_PROXY");
    }

    #[test]
    fn test_create_datalake_with_prod_config() {
        let dtl = Datalake::new(
            "username".to_string(),
            "password".to_string(),
            DatalakeSetting::prod(),
        );

        assert_eq!(dtl.settings.routes().authentication, "https://datalake.cert.orangecyberdefense.com/api/v2/auth/token/");
    }

    #[test]
    fn test_create_datalake_preprod_config() {
        let preprod_setting = DatalakeSetting::preprod();

        let dtl = Datalake::new(
            "username".to_string(),
            "password".to_string(),
            preprod_setting,
        );

        assert_eq!(dtl.settings.routes().authentication, "https://ti.extranet.mrti-center.com/api/v2/auth/token/");
    }

    #[test]
    fn test_run_with_authorization_token_fail_on_unclonable_request() {
        let preprod_setting = DatalakeSetting::preprod();
        let mut dtl = Datalake::new(
            "username".to_string(),
            "password".to_string(),
            preprod_setting,
        );
        // Create a random request
        let mut request = dtl.client.post(&dtl.settings.routes().authentication);
        // Set a streaming body that can't be cloned
        request = request.body(reqwest::blocking::Body::new(std::io::empty()));
        let err =  dtl.run_with_authorization_token(&request).err().unwrap();
        let expected_error_message = "Can't clone given request".to_string();
        assert_eq!(err, UnexpectedLibError(DetailedError::new(expected_error_message)));
    }

    #[test]
    fn test_refresh_tokens_with_no_existing_tokens() {
        let preprod_setting = DatalakeSetting::preprod();
        let dtl = Datalake::new(
            "username".to_string(),
            "password".to_string(),
            preprod_setting,
        );
        let err =  dtl.refresh_tokens().err().unwrap();
        let expected_error_message = "Refresh tokens called despite no token set".to_string();
        assert_eq!(err, UnexpectedLibError(DetailedError::new(expected_error_message)));
    }
}