/// Contains functions reused across multiple tests
#[cfg(test)]
use ocd_datalake_rs::{Datalake, DatalakeSetting};

/// Setup an Datalake reusable across tests
pub fn create_datalake() -> Datalake {
    let mut setting = DatalakeSetting::prod();
    setting.bulk_search_retry_interval_sec = 0;  // Speed up tests
    setting.set_base_url(mockito::server_url());
    Datalake::new(
        "username".to_string(),
        "password".to_string(),
        setting,
    )
}