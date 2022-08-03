#[cfg(test)]
mod tests {
    use mockito::mock;
    use ocd_datalake_rs::{Datalake, DatalakeSetting, RoutesSetting};

    /// Setup an Datalake reusable across tests
    fn create_datalake() -> Datalake {
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

    #[test]
    fn test_retrieve_token() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let mut dtl = create_datalake();

        let token = dtl.get_token();

        assert_eq!(token, "Token 123".to_string());
        token_mock.assert();
    }
}