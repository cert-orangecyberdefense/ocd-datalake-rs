/// Contains functions reused across multiple tests
#[cfg(test)]
use ocd_datalake_rs::{Datalake, DatalakeSetting};
use std::env;

/// Setup an Datalake reusable across tests
pub fn create_datalake() -> Datalake {
    let mut setting = DatalakeSetting::prod();

    // Speed up tests
    setting.bulk_search_retry_interval_sec = 0;
    setting.bulk_search_timeout_sec = 1;

    setting.set_base_url(mockito::server_url());
    env::remove_var("HTTP_PROXY");
    env::remove_var("HTTPS_PROXY");
    Datalake::new(
        "username".to_string(),
        "password".to_string(),
        setting,
    )
}