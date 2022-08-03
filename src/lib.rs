use std::collections::HashMap;
use config::FileFormat;
use reqwest::blocking::Client;
use serde_json::{Value};
use serde::Deserialize;


const CONFIG_ENV_PREFIX: &str = "OCD_DTL_RS";

#[derive(Deserialize, Clone, Debug)]
pub struct RoutesSetting {
    pub authentication: String,
    pub threat_library: String,
    pub patch_threat_library: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct DatalakeSetting {
    pub base_url: String,
    pub routes: RoutesSetting,
}

impl DatalakeSetting {
    pub fn replace_base_url(&mut self) {
        self.routes.authentication = self.routes.authentication.replace("{base_url}", &self.base_url);
        self.routes.threat_library = self.routes.threat_library.replace("{base_url}", &self.base_url);
        self.routes.patch_threat_library = self.routes.patch_threat_library.replace("{base_url}", &self.base_url);
    }
    pub fn new(config: &str) -> DatalakeSetting {
        let builder = config::Config::builder()
            .add_source(config::File::from_str(config, FileFormat::Ron))
            .add_source(config::Environment::with_prefix(CONFIG_ENV_PREFIX));
        let some_config = match builder.build() {
            Ok(valid_config) => valid_config,
            Err(e) => panic!("Config parse error: {:?}", e),
        };
        let mut settings = match some_config.get::<DatalakeSetting>("datalake_setting") {
            Ok(valid_settings) => { valid_settings }
            Err(e) => { panic!("Config is not as expected: {:?}", e) }
        };
        settings.replace_base_url();
        settings
    }

    #[allow(dead_code)]
    pub fn prod() -> Self {
        let prod_config_str = include_str!("../conf/conf.prod.ron");
        Self::new(prod_config_str)
    }

    #[allow(dead_code)]
    pub fn preprod() -> Self {
        let preprod_config_str = include_str!("../conf/conf.preprod.ron");
        Self::new(preprod_config_str)
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
    fn retrieve_api_token(&self) -> String {
        let mut token = "Token ".to_string();

        let auth_request = self.client.post(&self.settings.routes.authentication);
        let mut json_body = HashMap::new();
        json_body.insert("email", &self.username);
        json_body.insert("password", &self.password);
        let json_resp = match auth_request.json(&json_body).send() {
            Ok(resp) => { resp.json::<Value>().unwrap() }
            Err(err) => { panic!("Could not fetch API {:?}: {:?}", &self.settings.routes.authentication, err); }
        };
        let raw_token = json_resp["access_token"].as_str().unwrap();
        token.push_str(raw_token);
        token
    }

    /// Cached version of retrieve_api_token that return a new token only if needed
    pub fn get_token(&mut self) -> String {
        if self.access_token.is_none() {
            self.access_token = Some(self.retrieve_api_token());
        }
        let token = self.access_token.as_ref().unwrap().clone();
        token
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

        assert_eq!(dtl.settings.base_url, "https://datalake.cert.orangecyberdefense.com/api/v2");
        assert_eq!(dtl.settings.routes.authentication, "https://datalake.cert.orangecyberdefense.com/api/v2/auth/token/");
    }

    #[test]
    fn test_create_datalake_preprod_config() {
        let preprod_setting = DatalakeSetting::preprod();

        let dtl = Datalake::new(
            "username".to_string(),
            "password".to_string(),
            preprod_setting,
        );

        assert_eq!(dtl.settings.base_url, "https://ti.extranet.mrti-center.com/api/v2");
        assert_eq!(dtl.settings.routes.authentication, "https://ti.extranet.mrti-center.com/api/v2/auth/token/");
    }

    #[test]
    #[should_panic(expected = "Config parse error: 1:5: Non-whitespace trailing characters")]
    fn test_invalid_config() {
        DatalakeSetting::new("not a correct config");
    }
}