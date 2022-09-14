const CONFIG_ENV_PREFIX: &str = "OCD_DTL_RS";
const PREPROD_BASE_URL: &str = "https://ti.extranet.mrti-center.com/api/v2";

use config::FileFormat;
use serde::Deserialize;


#[derive(Deserialize, Clone, Debug)]
pub struct RoutesSetting {
    pub authentication: String,
    pub atom_values_extract: String,
    pub bulk_lookup: String,
    pub bulk_search: String,
    pub bulk_search_task: String,
    pub bulk_search_download: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct DatalakeSetting {
    base_url: String,
    routes: RoutesSetting,
    // raw routes with {base_url} in them
    formatted_routes: Option<RoutesSetting>,  // final routes, only set after replace_base_url is called
    // Other settings
    pub bulk_lookup_chunk_size: usize,
    pub bulk_search_retry_interval_sec: u64,
    pub bulk_search_timeout_sec: u64,
}

impl DatalakeSetting {
    pub fn base_url(&self) -> &String {
        &self.base_url
    }

    pub fn set_base_url(&mut self, base_url: String) {
        self.base_url = base_url;
        self.replace_base_url()
    }

    fn replace_base_url(&mut self) {
        self.formatted_routes = Some(RoutesSetting {
            authentication: self.routes.authentication.replace("{base_url}", &self.base_url),
            atom_values_extract: self.routes.atom_values_extract.replace("{base_url}", &self.base_url),
            bulk_lookup: self.routes.bulk_lookup.replace("{base_url}", &self.base_url),
            bulk_search: self.routes.bulk_search.replace("{base_url}", &self.base_url),
            bulk_search_task: self.routes.bulk_search_task.replace("{base_url}", &self.base_url),
            bulk_search_download: self.routes.bulk_search_download.replace("{base_url}", &self.base_url),
        })
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

    pub fn routes(&self) -> &RoutesSetting {
        self.formatted_routes.as_ref().expect("Formatted routes could not be found")
    }

    #[allow(dead_code)]
    pub fn prod() -> Self {
        let prod_config_str = include_str!("../../conf/conf.prod.ron");
        Self::new(prod_config_str)
    }

    #[allow(dead_code)]
    pub fn preprod() -> Self {
        let mut setting = Self::prod();
        setting.set_base_url(PREPROD_BASE_URL.to_string());
        setting
    }
}

#[cfg(test)]
mod tests {
    use crate::DatalakeSetting;


    #[test]
    fn test_create_datalake_with_prod_config() {
        let prod_setting = DatalakeSetting::prod();

        assert_eq!(prod_setting.base_url, "https://datalake.cert.orangecyberdefense.com/api/v2");
    }

    #[test]
    fn test_preprod_config() {
        let preprod_setting = DatalakeSetting::preprod();
        assert_eq!(preprod_setting.base_url, "https://ti.extranet.mrti-center.com/api/v2");
    }

    #[test]
    #[should_panic(expected = "Config parse error: 1:5: Non-whitespace trailing characters")]
    fn test_invalid_config() {
        DatalakeSetting::new("not a correct config");
    }
}