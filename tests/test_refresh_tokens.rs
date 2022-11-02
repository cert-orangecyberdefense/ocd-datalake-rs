#[path = "common.rs"]
mod common;

#[cfg(test)]
mod tests {
    use mockito::Matcher::Json;
    use mockito::mock;
    use serde_json::json;
    use crate::common;

    #[test]
    fn test_extract_atom_type() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let refresh_token_mock = mock("POST", "/auth/refresh-token/")
            .match_header("Authorization", "Token 456")
            .with_status(200)
            .with_body(r#"{"access_token": "refreshed_access_token"}"#)
            .create();
        let extract_mock_on_expired_token = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({"content":"domain.com 4.4.4.4 1.1.1.1"})))
            .match_header("Authorization", "Token 123")
            .with_status(401)
            .with_body(r#"{"msg":"Token has expired"}"#)
            .create();
        let extract_mock = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({"content":"domain.com 4.4.4.4 1.1.1.1"})))
            .match_header("Authorization", "Token refreshed_access_token")
            .with_status(200)
            .with_body(r#"{"found":2,"not_found":["1.1.1.1"],"results":{"domain":["domain.com"],"ip":["4.4.4.4"]}}"#)
            .create();
        let mut dtl = common::create_datalake();
        let atom_values = vec!["domain.com", "4.4.4.4", "1.1.1.1"];
        let atom_values_string: Vec<String> = atom_values.iter().map(|x| x.to_string()).collect();

        let result = dtl.extract_atom_type(&atom_values_string).unwrap();

        for mock in [token_mock, refresh_token_mock, extract_mock_on_expired_token, extract_mock] {
            mock.assert()  // Check url were called 1 times each
        }

        let domain = result.get(atom_values[0]).unwrap();
        assert_eq!(domain, "domain");
        let ip1 = result.get(atom_values[1]).unwrap();
        assert_eq!(ip1, "ip");
        let ip2 = result.get(atom_values[2]);
        assert_eq!(ip2, None);
    }
}