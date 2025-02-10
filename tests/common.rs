/// Contains functions reused across multiple tests
#[cfg(test)]
use ocd_datalake_rs::{Datalake, DatalakeSetting};

/// Setup an Datalake reusable across tests
pub fn create_datalake() -> Datalake {
    let mut setting = DatalakeSetting::prod();

    // Speed up tests
    setting.bulk_search_retry_interval_sec = 0;
    setting.bulk_search_timeout_sec = 1;

    setting.set_base_url(mockito::server_url());
    Datalake::new(
        Some("username".to_string()),
        Some("password".to_string()),
        None,
        setting,
    )
}