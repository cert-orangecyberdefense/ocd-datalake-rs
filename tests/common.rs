/// Contains functions reused across multiple tests
#[cfg(test)]
use ocd_datalake_rs::{Datalake, DatalakeSetting, RoutesSetting};

/// Setup an Datalake reusable across tests
pub fn create_datalake() -> Datalake {
    let mut setting = DatalakeSetting {
        base_url: mockito::server_url(),
        routes: RoutesSetting {
            authentication: "{base_url}/auth/token/".to_string(),
            threat_library: "{base_url}/mrti/tag-subcategory/filtered/".to_string(),
            patch_threat_library: "{base_url}/mrti/tag-subcategory/{sub_category_id}/".to_string(),
        },
    };
    setting.replace_base_url();
    Datalake::new(
        "username".to_string(),
        "password".to_string(),
        setting,
    )
}