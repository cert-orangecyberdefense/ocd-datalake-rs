#[cfg(test)]
mod tests {
    use mockito::mock;
    use ocd_datalake_rs::{Datalake, DatalakeSetting};

    /// Setup an api_setting reusable across tests
    fn create_api_client() -> Datalake {
        let mut api_setting = DatalakeSetting {
            base_url: mockito::server_url(),
            authentication_url: "{base_url}/auth/token/".to_string(),
            threat_library_url: "{base_url}/mrti/tag-subcategory/filtered/".to_string(),
            patch_threat_library_url: "{base_url}/mrti/tag-subcategory/{sub_category_id}/".to_string(),
        };
        api_setting.replace_base_url();
        Datalake::new(
            "username".to_string(),
            "password".to_string(),
            api_setting,
        )
    }

    #[test]
    fn test_retrieve_token() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let mut api_client = create_api_client();

        let token = api_client.get_token();

        assert_eq!(token, "Token 123".to_string());
        token_mock.assert();
    }
}