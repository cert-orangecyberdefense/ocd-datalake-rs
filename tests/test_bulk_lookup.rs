#[path = "common.rs"]
mod common;

#[cfg(test)]
mod tests {
    use mockito::mock;
    use crate::common;


    #[test]
    #[ignore]  // TODO
    fn test_retrieve_token() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let lookup_mock = mock("POST", "/wow")
            .with_status(200)
            .with_body(r#"{"access_token": "123"}"#)
            .create();
        let mut dtl = common::create_datalake();

        let token = dtl.get_token();

        token_mock.assert();
        lookup_mock.assert();
    }

    #[test]
    fn test_extract_atom_type() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let lookup_mock = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(r#"{"content":"domain.com 4.4.4.4 1.1.1.1"}"#) // TODO replace with json! call
            .match_header("Authorization", "Token 123")
            .with_status(200)
            .with_body(r#"{"found":2,"not_found":["1.1.1.1"],"results":{"domain":["domain.com"],"ip":["4.4.4.4"]}}"#)
            .create();
        let mut dtl = common::create_datalake();
        let atom_values = vec!["domain.com", "4.4.4.4", "1.1.1.1"];
        let atom_values_string: Vec<String> = atom_values.iter().map(|x| x.to_string()).collect();

        let result = dtl.extract_atom_type(&atom_values_string);

        // Check mock called happened
        token_mock.assert();
        lookup_mock.assert();

        eprintln!("result = {:?}", result);
        let domain = result.get(atom_values[0]).unwrap();
        assert_eq!(domain, "domain");
        let ip1 = result.get(atom_values[1]).unwrap();
        assert_eq!(ip1, "ip");
        let ip2 = result.get(atom_values[2]);
        assert_eq!(ip2, None);
    }
}