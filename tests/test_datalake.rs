#[path = "common.rs"]
mod common;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Mutex;
    use lazy_static::lazy_static;
    use mockito::mock;
    use ocd_datalake_rs::{Datalake, DatalakeSetting};
    use crate::common;

    lazy_static! {
        static ref WORKDIR_MUTEX: Mutex<()> = Mutex::default();  // Test modifying the workdir should take the mutex
    }

    #[test]
    fn test_retrieve_token() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let mut dtl = common::create_datalake();

        let token = dtl.get_token();

        assert_eq!(token.unwrap(), "Token 123".to_string());
        token_mock.assert();
    }

    #[test]
    fn test_error_on_retrieve_token() {
        let example_filename = "examples/custom_config.ron";
        let contents = {
            let _mutex = WORKDIR_MUTEX.lock().unwrap();  // the file is a shared resource
            fs::read_to_string(example_filename).unwrap()
        };
        let mut dtl = Datalake::new(
            "username".to_string(),
            "password".to_string(),
            DatalakeSetting::new(contents.as_str()),
        );

        let err = dtl.get_token().err().unwrap();
        assert_eq!(err.to_string(), "HTTP Error Could not fetch API for url https://custom_host/auth/token/");
    }

    /// Check config is not dependant to the workdir
    #[test]
    fn test_default_datalake_on_another_workdir() {
        let _mutex = WORKDIR_MUTEX.lock().unwrap();
        let test_work_dir = std::env::current_dir().unwrap();
        let tmp = Path::new("/tmp");
        assert!(std::env::set_current_dir(&tmp).is_ok());
        Datalake::new(
            "username".to_string(),
            "password".to_string(),
            DatalakeSetting::prod(),
        );

        std::env::set_current_dir(test_work_dir).unwrap();  // Reset work dir as others tests need it
    }

    #[test]
    fn test_prod_setting() {
        let prod_setting = DatalakeSetting::prod();

        assert_eq!(prod_setting.base_url(), "https://datalake.cert.orangecyberdefense.com/api/v2");
        assert_eq!(prod_setting.routes().authentication, "https://datalake.cert.orangecyberdefense.com/api/v2/auth/token/");
    }

    #[test]
    fn test_change_base_url_setting() {
        let mut base_setting = DatalakeSetting::prod();
        base_setting.set_base_url("base_url.com/api/v2".to_string());
        assert_eq!(base_setting.routes().authentication, "base_url.com/api/v2/auth/token/");
    }

    #[test]
    fn test_custom_datalake_settings_from_file() {
        let example_filename = "examples/custom_config.ron";
        let contents = {  // take the lock only to read the file
            let _mutex = WORKDIR_MUTEX.lock().unwrap();
            fs::read_to_string(example_filename).expect("Error reading the config file")
        };  // lock is released
        let _dtl = Datalake::new(
            "username".to_string(),
            "password".to_string(),
            DatalakeSetting::new(contents.as_str()),
        );
    }
}