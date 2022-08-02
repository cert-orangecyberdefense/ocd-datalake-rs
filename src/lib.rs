use std::collections::HashMap;
use reqwest::blocking::Client;
use serde_json::{Value};
use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct DatalakeSetting {
    pub base_url: String,
    pub authentication_url: String,
    pub threat_library_url: String,
    pub patch_threat_library_url: String,
}

impl DatalakeSetting {
    pub fn replace_base_url(&mut self) {
        self.authentication_url = self.authentication_url.replace("{base_url}", &self.base_url);
        self.threat_library_url = self.threat_library_url.replace("{base_url}", &self.base_url);
        self.patch_threat_library_url = self.patch_threat_library_url.replace("{base_url}", &self.base_url);
    }
}

#[derive(Clone, Debug)]
pub struct Datalake {
    settings: DatalakeSetting,
    username: String,
    password: String,
    client: Client,
    token: Option<String>
}

impl Datalake {
    pub fn new(username: String, password: String, settings: DatalakeSetting) -> Self {
        Datalake {
            settings,
            username,
            password,
            client: Client::new(),
            token: None,
        }
    }

    fn retrieve_api_token(&self) -> String {
        let mut token = "Token ".to_string();

        let auth_request = self.client.post(&self.settings.authentication_url);
        let mut json_body = HashMap::new();
        json_body.insert("email", &self.username);
        json_body.insert("password", &self.password);
        let json_resp = match auth_request.json(&json_body).send() {
            Ok(resp) => { resp.json::<Value>().unwrap() }
            Err(err) => { panic!("Could not fetch API {:?}: {:?}", &self.settings.threat_library_url, err); }
        };
        let raw_token = json_resp["access_token"].as_str().unwrap();
        token.push_str(raw_token);
        token
    }

    /// Cached version of retrieve_api_token that return a new token only if needed
    pub fn get_token(&mut self) -> String {
        if self.token.is_none() {
            self.token = Some(self.retrieve_api_token());
        }
        let token = self.token.as_ref().unwrap().clone();
        token
    }
}