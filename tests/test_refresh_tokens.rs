#[path = "common.rs"]
mod common;

#[cfg(test)]
mod tests {
    use mockito::Matcher::Json;
    use mockito::mock;
    use reqwest::StatusCode;
    use serde_json::json;
    use ocd_datalake_rs::error::DatalakeError::AuthenticationError;
    use ocd_datalake_rs::error::DetailedError;
    use crate::common;

    #[test]
    fn test_refresh_token_on_extract_atom_type() {
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
            .match_body(Json(json!({"content":"domain.com 4.4.4.4 1.1.1.1", "treat_hashes_like": "file"})))
            .match_header("Authorization", "Token 123")
            .with_status(401)
            .with_body(r#"{"msg":"Token has expired"}"#)
            .create();
        let extract_mock = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({"content":"domain.com 4.4.4.4 1.1.1.1", "treat_hashes_like": "file"})))
            .match_header("Authorization", "Token refreshed_access_token")
            .with_status(200)
            .with_body(r#"{"found":2,"not_found":["1.1.1.1"],"results":{"domain":["domain.com"],"ip":["4.4.4.4"]}}"#)
            .create();
        let mut dtl = common::create_datalake();
        let atom_values = vec!["domain.com", "4.4.4.4", "1.1.1.1"];
        let atom_values_string: Vec<String> = atom_values.iter().map(|x| x.to_string()).collect();

        let result = dtl.extract_atom_type(&atom_values_string, "file").unwrap();

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

    #[test]
    fn test_reauth_on_extract_atom_type() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let refresh_token_mock = mock("POST", "/auth/refresh-token/")
            .match_header("Authorization", "Token 456")
            .with_status(401)
            .with_body(r#"{"msg": "Token has expired"}"#)
            .create();
        let reauth_token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "new_access_token","refresh_token": "not_tested"}"#)
            .create();
        let extract_mock_on_expired_token = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({"content":"domain.com 4.4.4.4 1.1.1.1", "treat_hashes_like": "file"})))
            .match_header("Authorization", "Token 123")
            .with_status(401)
            .with_body(r#"{"msg":"Token has expired"}"#)
            .create();
        let extract_mock = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({"content":"domain.com 4.4.4.4 1.1.1.1", "treat_hashes_like": "file"})))
            .match_header("Authorization", "Token new_access_token")
            .with_status(200)
            .with_body(r#"{"found":2,"not_found":["1.1.1.1"],"results":{"domain":["domain.com"],"ip":["4.4.4.4"]}}"#)
            .create();
        let mut dtl = common::create_datalake();
        let atom_values = vec!["domain.com", "4.4.4.4", "1.1.1.1"];
        let atom_values_string: Vec<String> = atom_values.iter().map(|x| x.to_string()).collect();

        let result = dtl.extract_atom_type(&atom_values_string, "file").unwrap();

        for mock in [
            token_mock,
            refresh_token_mock,
            reauth_token_mock,
            extract_mock_on_expired_token,
            extract_mock,
        ] {
            mock.assert()  // Check url were called 1 times each
        }

        let domain = result.get(atom_values[0]).unwrap();
        assert_eq!(domain, "domain");
        let ip1 = result.get(atom_values[1]).unwrap();
        assert_eq!(ip1, "ip");
        let ip2 = result.get(atom_values[2]);
        assert_eq!(ip2, None);
    }

    #[test]
    fn test_extract_atom_type_no_loop_on_401() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let refresh_token_mock = mock("POST", "/auth/refresh-token/")
            .match_header("Authorization", "Token 456")
            .with_status(200)
            .with_body(r#"{"access_token": "refreshed_access_token"}"#)
            .create();
        let token_expired_msg = r#"{"msg":"Token has expired"}"#;
        let extract_mock_on_expired_token = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({"content":"domain.com 4.4.4.4 1.1.1.1", "treat_hashes_like": "file"})))
            .match_header("Authorization", "Token 123")
            .with_status(401)
            .with_body(token_expired_msg)
            .create();
        let extract_mock_on_refreshed_token = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({"content":"domain.com 4.4.4.4 1.1.1.1", "treat_hashes_like": "file"})))
            .match_header("Authorization", "Token refreshed_access_token")
            .with_status(401)  // Keeps returning 401 on refreshed token
            .with_body(token_expired_msg)
            .expect(1)  // Should be called only a single time
            .create();
        let mut dtl = common::create_datalake();
        let atom_values = vec!["domain.com", "4.4.4.4", "1.1.1.1"];
        let atom_values_string: Vec<String> = atom_values.iter().map(|x| x.to_string()).collect();

        let result = dtl.extract_atom_type(&atom_values_string, "file");

        for mock in [
            token_mock,
            refresh_token_mock,
            extract_mock_on_expired_token,
            extract_mock_on_refreshed_token,
        ] {
            mock.assert()  // Check url were called 1 times each
        }

        let err = result.err().unwrap();
        assert_eq!(err, AuthenticationError(DetailedError {
            summary: "401 response despite refreshed token".to_string(),
            api_url: Some(format!("{}/mrti/threats/atom-values-extract/", mockito::server_url())),
            api_response: Some(token_expired_msg.to_string()),
            api_status_code: Some(StatusCode::UNAUTHORIZED),
        }));
    }

    #[test]
    fn test_refresh_token_on_bulk_lookup() {
        let atom_values = vec![
            "620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e",
            "ef3363dfe2515b826584ab53c4bb7812",
            "jeithe7eijeefohch3qu.probes.site",
        ];
        let atom_values_string: Vec<String> = atom_values.iter().map(|x| x.to_string()).collect();

        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let refresh_token_mock = mock("POST", "/auth/refresh-token/")
            .match_header("Authorization", "Token 456")
            .with_status(200)
            .with_body(r#"{"access_token": "refreshed_access_token"}"#)
            .create();
        let extract_mock = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({
                "content":"620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e ef3363dfe2515b826584ab53c4bb7812 jeithe7eijeefohch3qu.probes.site",
                "treat_hashes_like": "file",
            })))
            .with_status(200)
            .with_body(json!({
                "found": 3,
                "not_found": [],
                "results": {
                    "file": [
                        "620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e",
                        "ef3363dfe2515b826584ab53c4bb7812",
                    ],
                    "fqdn": [
                        "jeithe7eijeefohch3qu.probes.site",
                    ],
                }
            }).to_string())
            .create();
        let lookup_mock_on_expired_token = mock("POST", "/mrti/threats/bulk-lookup/")
            .match_header("Authorization", "Token 123")
            .with_status(401)
            .with_body(r#"{"msg":"Token has expired"}"#)
            .create();
        let csv_body = r#"hashkey,atom_type,search_phrase,atom_value,atom_value_best_matching,threat_found,access_permission,events_number,first_seen,last_updated,last_updated_by_source,threat_types,ddos.score.risk,fraud.score.risk,hack.score.risk,leak.score.risk,malware.score.risk,phishing.score.risk,scam.score.risk,scan.score.risk,spam.score.risk
000001a049b612930338a3ff293967d6,file,620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e,620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e,620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e,True,True,7,2021-11-16T03:39:56Z,2022-08-05T08:37:26Z,2022-08-01T08:37:25Z,,1,1,1,1,5,8,,,
570c18ccf35a7003789f4332cb63bfce,fqdn,jeithe7eijeefohch3qu.probes.site,jeithe7eijeefohch3qu.probes.site,jeithe7eijeefohch3qu.probes.site,True,True,11,2020-11-25T21:11:41Z,2021-05-09T05:53:40Z,,,,,12,,13,12,,,
736e1acf892a27598d65a52136122699,,ef3363dfe2515b826584ab53c4bb7812,ef3363dfe2515b826584ab53c4bb7812,,False,False,,,,,,,,,,,,,,
"#;
        let lookup_mock = mock("POST", "/mrti/threats/bulk-lookup/")
            .match_header("Authorization", "Token refreshed_access_token")
            .match_body(Json(json!({
                    "hashkey_only": false,
                    "file": [
                        "620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e",
                        "ef3363dfe2515b826584ab53c4bb7812"
                    ],
                    "fqdn": [
                        "jeithe7eijeefohch3qu.probes.site"
                    ]
                }))
            )
            .with_status(200)
            .with_body(csv_body)
            .create();
        let mut dtl = common::create_datalake();

        let lookup_result = dtl.bulk_lookup(atom_values_string, "file").unwrap();

        token_mock.assert();
        refresh_token_mock.assert();
        extract_mock.assert();
        lookup_mock_on_expired_token.assert();
        lookup_mock.assert();

        assert_eq!(lookup_result, csv_body);
    }
}