use std::collections::HashMap;
use config::FileFormat;
use reqwest::blocking::Client;
use serde_json::{Value};
use serde::Deserialize;


const CONFIG_ENV_PREFIX: &str = "OCD_DTL_RS";
const CONFIG_PROD_FILE: &str = "conf/conf.prod.ron";
const CONFIG_PREPROD_FILE: &str = "conf/conf.preprod.ron";

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
    pub fn new(config_file: &str) -> DatalakeSetting {
        let builder = config::Config::builder()
            .add_source(config::File::new(config_file, FileFormat::Ron))
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
}


impl Default for DatalakeSetting {
    fn default() -> Self {
        Self::new(CONFIG_PROD_FILE)
    }
}

#[derive(Clone, Debug)]
pub struct Datalake {
    settings: DatalakeSetting,
    username: String,
    password: String,
    client: Client,
    token: Option<String>,
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

        let auth_request = self.client.post(&self.settings.routes.authentication);
        let mut json_body = HashMap::new();
        json_body.insert("email", &self.username);
        json_body.insert("password", &self.password);
        let json_resp = match auth_request.json(&json_body).send() {
            Ok(resp) => { resp.json::<Value>().unwrap() }
            Err(err) => { panic!("Could not fetch API {:?}: {:?}", &self.settings.routes.threat_library, err); }
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

#[cfg(test)]
mod tests {
    use crate::{CONFIG_PREPROD_FILE, Datalake, DatalakeSetting};

    #[test]
    fn test_create_datalake_with_default_config() {
        let dtl = Datalake::new(
            "username".to_string(),
            "password".to_string(),
            DatalakeSetting::default(),
        );

        assert_eq!(dtl.settings.base_url, "https://datalake.cert.orangecyberdefense.com");
        assert_eq!(dtl.settings.routes.authentication, "https://datalake.cert.orangecyberdefense.com/auth/token/");
    }

    #[test]
    fn test_create_datalake_preprod_config() {
        let preprod_setting = DatalakeSetting::new(CONFIG_PREPROD_FILE);

        let dtl = Datalake::new(
            "username".to_string(),
            "password".to_string(),
            preprod_setting,
        );

        assert_eq!(dtl.settings.base_url, "https://ti.extranet.mrti-center.com");
        assert_eq!(dtl.settings.routes.authentication, "https://ti.extranet.mrti-center.com/auth/token/");
    }

    #[test]
    #[should_panic(expected = "Config parse error: configuration file \"/not/existing/path.ron\"")]
    fn test_config_file_not_present() {
        DatalakeSetting::new("/not/existing/path.ron");
    }

    // TODO preprod and prod config have the same routes
}