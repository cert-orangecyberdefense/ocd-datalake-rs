mod setting;

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use reqwest::blocking::Client;
use serde_json::{json, Map, Value};
use crate::DatalakeError::AuthenticationError;
pub use crate::setting::{DatalakeSetting, RoutesSetting};

#[derive(Debug)]
pub enum DatalakeError {
    AuthenticationError(String),
    HttpError(String),
    ParseError(String),
}


impl fmt::Display for DatalakeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DatalakeError::AuthenticationError(err) => write!(f, "Authentication Error {}", err),
            DatalakeError::HttpError(err) => write!(f, "HTTP Error {}", err),
            DatalakeError::ParseError(err) => write!(f, "Parse Error {}", err),
        }
    }
}

impl From<reqwest::Error> for DatalakeError {
    fn from(error: reqwest::Error) -> Self {
        if error.is_decode() {
            return Self::ParseError(format!("{}", error));
        }
        // default to http error
        let url = match error.url() {
            None => { "<no url>"}
            Some(url) => { url.as_str() }
        };
        Self::HttpError(format!("Could not fetch API for url {}", url))
    }
}

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

        let auth_request = self.client.post(&self.settings.routes().authentication);
        let mut json_body = HashMap::new();
        json_body.insert("email", &self.username);
        json_body.insert("password", &self.password);
        let resp = auth_request.json(&json_body).send()?;
        let json_resp = resp.json::<Value>()?;
        let raw_token = json_resp["access_token"].as_str();
        let op_token = match raw_token {
            None => {
                let error_message = format!("Invalid credentials ({json_resp})");
                return Err(AuthenticationError(error_message));
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
    pub fn extract_atom_type(&mut self, atom_values: &[String]) -> BTreeMap<String, String> {    // TODO return results
        let url = self.settings.routes().atom_values_extract.clone();
        let mut request = self.client.post(&url);
        request = request.header("Authorization", self.get_token().unwrap());  // TODO
        let mut joined_atom_values = String::from(&atom_values[0]);
        for value in atom_values.iter().skip(1) {
            joined_atom_values.push(' ');
            joined_atom_values.push_str(value);
        }
        let json_body = json!({
            "content": joined_atom_values,
        });
        let json_resp = match request.json(&json_body).send() {
            Ok(resp) => { resp.json::<Value>().unwrap() }
            Err(err) => { panic!("Could not fetch API {:?}: {:?}", &url, err); }
        };
        let results_value = json_resp.get("results").expect("results key not returned by the API");
        let results = results_value.as_object().expect("result key not as expected");
        let mut extracted_atom_types = BTreeMap::new();
        for (atom_type, atoms) in results {
            for atom in atoms.as_array().unwrap() {
                let atom_value = atom.as_str().unwrap().to_string();
                extracted_atom_types.insert(atom_value, atom_type.clone());
            }
        }
        extracted_atom_types
    }

    /// Return a CSV of the bulk lookup for given threats
    ///
    /// Threats have their atom type automatically defined (with hash meaning a File type)
    pub fn bulk_lookup(&mut self, atom_values: Vec<String>) -> String {  // TODO return results
        let url = self.settings.routes().bulk_lookup.clone();

        // Construct the body by identifying the atom types
        let extracted = self.extract_atom_type(&atom_values);
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
            .header("Authorization", self.get_token().unwrap())  // TODO
            .header("Accept", "text/csv");
        match request.json(&body).send() {
            Ok(csv_resp) => { csv_resp.text().unwrap() }
            Err(err) => { panic!("Could not fetch API {:?}: {:?}", &url, err); }
        }
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