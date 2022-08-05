#[path = "common.rs"]
mod common;

#[cfg(test)]
mod tests {
    use mockito::mock;
    use crate::common;


    // #[test]
    // fn test_retrieve_token() {
    //     let token_mock = mock("POST", "/auth/token/")
    //         .with_status(200)
    //         .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
    //         .create();
    //     let mut dtl = common::create_datalake();
    //
    //     let token = dtl.get_token();
    //
    //     assert_eq!(token, "Token 123".to_string());
    //     token_mock.assert();
    // }
}