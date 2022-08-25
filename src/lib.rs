extern crate core;

pub mod setting;
pub mod error;
pub mod bulk_search;

use std::collections::{BTreeMap, HashMap};
use std::thread;
use std::time::{Duration, Instant};
use std::str::FromStr;
use reqwest::blocking::Client;
use serde_json::{json, Map, Value};
use crate::bulk_search::{create_bulk_search_task, download_bulk_search, get_bulk_search_task, State};
use crate::error::{DatalakeError, DetailedError};
use crate::DatalakeError::{ApiError, AuthenticationError, TimeoutError};
pub use crate::setting::{DatalakeSetting, RoutesSetting};

pub const ATOM_VALUE_QUERY_FIELD: &str = "atom_value";

#[derive(Clone, Debug)]
pub struct Datalake {
    settings: DatalakeSetting,
    username: String,
    password: String,
    client: Client,
    access_token: Option<String>,
}

impl Datalake {
    pub fn new(username: String, password: String, settings: DatalakeSetting) -> Self {
        Datalake {
            settings,
            username,
            password,
            client: Client::new(),
            access_token: None,
        }
    }
    // TODO handle expired access / refresh token
    fn retrieve_api_token(&self) -> Result<String, DatalakeError> {
        let mut token = "Token ".to_string();

        let url = &self.settings.routes().authentication;
        let auth_request = self.client.post(url);
        let mut json_body = HashMap::new();
        json_body.insert("email", &self.username);
        json_body.insert("password", &self.password);
        let resp = auth_request.json(&json_body).send()?;
        let status_code = resp.status();
        let json_resp = resp.json::<Value>()?;
        let raw_token = json_resp["access_token"].as_str();
        let op_token = match raw_token {
            None => {
                let err = DetailedError {
                    summary: "Invalid credentials".to_string(),
                    api_url: Some(url.to_string()),
                    api_response: Some(json_resp.to_string()),
                    api_status_code: Some(status_code),
                };
                return Err(AuthenticationError(err));
            }
            Some(op_token) => { op_token }
        };
        token.push_str(op_token);
        Ok(token)
    }

    /// Cached version of retrieve_api_token that return a new token only if needed
    pub fn get_token(&mut self) -> Result<String, DatalakeError> {
        if self.access_token.is_none() {
            self.access_token = Some(self.retrieve_api_token()?);
        }
        let token = self.access_token.as_ref().unwrap().clone();
        Ok(token)
    }

    /// Return the atom types based on the given atom_values
    pub fn extract_atom_type(&mut self, atom_values: &[String]) -> Result<BTreeMap<String, String>, DatalakeError> {
        let url = self.settings.routes().atom_values_extract.clone();
        let mut request = self.client.post(&url);
        request = request.header("Authorization", self.get_token()?);
        let mut joined_atom_values = String::from(&atom_values[0]);
        for value in atom_values.iter().skip(1) {
            joined_atom_values.push(' ');
            joined_atom_values.push_str(value);
        }
        let json_body = json!({
            "content": joined_atom_values,
        });
        let resp = request.json(&json_body).send()?;
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
        let url = self.settings.routes().bulk_lookup.clone();

        // Construct the body by identifying the atom types
        let extracted = self.extract_atom_type(&atom_values)?;
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

        let request = self.client.post(&url)
            .header("Authorization", self.get_token()?)
            .header("Accept", "text/csv");
        let csv_resp = request.json(&body).send()?.text()?;
        Ok(csv_resp)
    }

    /// Retrieve all the results of a query using its query_hash.
    ///
    /// Fields returned depend on query_fields.
    /// For now the result is returned as a CSV.
    /// > :warning: the function is blocking while the bulk search is being processed by the API (up to 1h)
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
            let state: State = match State::from_str(&task.state) {
                Ok(state) => state,
                Err(_) => {
                    return Err(ApiError(DetailedError::new(format!("Bulk search is in unexpected state: {}", task.state))));
                }
            };
            bulk_search_is_ready = match state {
                State::DONE => true,
                State::NEW | State::QUEUED | State::IN_PROGRESS => false,  // bulk search is not ready yet
                State::CANCELLED | State::FAILED_ERROR | State::FAILED_TIMEOUT => {
                    return Err(ApiError(DetailedError::new(format!("Bulk search is in {state} state"))));
                }
            }
        }
        download_bulk_search(self, task_uuid)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Datalake, DatalakeSetting};

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
}