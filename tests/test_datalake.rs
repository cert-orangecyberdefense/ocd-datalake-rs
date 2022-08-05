#[path = "common.rs"]
mod common;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use mockito::mock;
    use ocd_datalake_rs::{Datalake, DatalakeSetting};
    use crate::common;

    #[test]
    fn test_retrieve_token() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let mut dtl = common::create_datalake();

        let token = dtl.get_token();

        assert_eq!(token, "Token 123".to_string());
        token_mock.assert();
    }

    /// Check config is not dependant to the workdir
    #[test]
    fn test_default_datalake_on_another_workdir() {
        let tmp = Path::new("/tmp");
        assert!(std::env::set_current_dir(&tmp).is_ok());
        Datalake::new(
            "username".to_string(),
            "password".to_string(),
            DatalakeSetting::prod(),
        );
    }

    #[test]
    fn test_custom_datalake_settings_from_file() {
        let example_filename = "examples/custom_config.ron";
        let contents = fs::read_to_string(example_filename).expect("Error reading the config file");
        let _dtl = Datalake::new(
            "username".to_string(),
            "password".to_string(),
            DatalakeSetting::new(contents.as_str()),
        );
    }
}