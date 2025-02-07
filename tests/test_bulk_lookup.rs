#[path = "common.rs"]
mod common;

#[cfg(test)]
mod tests {
    use mockito::Matcher::Json;
    use mockito::mock;
    use reqwest::StatusCode;
    use serde_json::json;
    use ocd_datalake_rs::{Datalake, DatalakeSetting};
    use ocd_datalake_rs::error::DatalakeError::ApiError;
    use crate::common;

    #[test]
    fn test_extract_atom_type() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let extract_mock = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({"content":"domain.com 4.4.4.4 1.1.1.1", "treat_hashes_like": "file"})))
            .match_header("Authorization", "Token 123")
            .with_status(200)
            .with_body(r#"{"found":2,"not_found":["1.1.1.1"],"results":{"domain":["domain.com"],"ip":["4.4.4.4"]}}"#)
            .create();
        let mut dtl = common::create_datalake();
        let atom_values = vec!["domain.com", "4.4.4.4", "1.1.1.1"];
        let atom_values_string: Vec<String> = atom_values.iter().map(|x| x.to_string()).collect();

        let result = dtl.extract_atom_type(&atom_values_string, "file").unwrap();

        // Check mock called happened
        token_mock.assert();
        extract_mock.assert();

        let domain = result.get(atom_values[0]).unwrap();
        assert_eq!(domain, "domain");
        let ip1 = result.get(atom_values[1]).unwrap();
        assert_eq!(ip1, "ip");
        let ip2 = result.get(atom_values[2]);
        assert_eq!(ip2, None);
    }

    #[test]
    fn test_extract_atom_type_with_no_result() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let extract_mock = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({"content":"123", "treat_hashes_like": "file"})))
            .match_header("Authorization", "Token 123")
            .with_status(200)
            .with_body(r#"{"found":0,"not_found":["123"],"results":{}}"#)
            .create();
        let mut dtl = common::create_datalake();
        let atom_values = vec!["123".to_string()];

        let result = dtl.extract_atom_type(&atom_values, "file").unwrap();

        // Check mock called happened
        token_mock.assert();
        extract_mock.assert();

        assert!(result.is_empty());  // No result returned
    }

    #[test]
    fn test_extract_atom_type_with_error() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let api_response = r#"{"messages":{"atom_type":["'wow' is not a valid choice. Valid values: 'apk',"]}}"#;
        let extract_mock = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({"content":"123", "treat_hashes_like": "file"})))
            .match_header("Authorization", "Token 123")
            .with_status(422)
            .with_body(api_response)
            .create();
        let mut dtl = common::create_datalake();
        let atom_values = vec!["123".to_string()];

        let err = dtl.extract_atom_type(&atom_values, "file").err().unwrap();
        assert_eq!(
            err.to_string(),
            format!("API Error extracted API response not as expected"),
        );
        if let ApiError(detailed_err) = err {
            assert_eq!(detailed_err.api_response.unwrap(), api_response);
        } else {
            panic!("Unexpected error!")
        }

        // Check mock called happened
        token_mock.assert();
        extract_mock.assert();
    }

    #[test]
    fn test_extract_atom_type_with_non_expected_result() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let api_response = r#"{"results":"API changed, results is now a string"}"#;
        let extract_mock = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({"content":"123", "treat_hashes_like": "file"})))
            .match_header("Authorization", "Token 123")
            .with_status(200)
            .with_body(api_response)
            .create();
        let mut dtl = common::create_datalake();
        let atom_values = vec!["123".to_string()];

        let err = dtl.extract_atom_type(&atom_values, "file").err().unwrap();
        assert_eq!(
            err.to_string(),
            format!("API Error extracted API response not as expected"),
        );

        if let ApiError(detailed_err) = err {
            assert_eq!(detailed_err.api_response.unwrap(), api_response);
        } else {
            panic!("Unexpected error!")
        }

        // Check mock called happened
        token_mock.assert();
        extract_mock.assert();
    }


    #[test]
    fn test_bulk_lookup_on_few_values() {
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
        let csv_body = r#"hashkey,atom_type,search_phrase,atom_value,atom_value_best_matching,threat_found,access_permission,events_number,first_seen,last_updated,last_updated_by_source,threat_types,ddos.score.risk,fraud.score.risk,hack.score.risk,leak.score.risk,malware.score.risk,phishing.score.risk,scam.score.risk,scan.score.risk,spam.score.risk
000001a049b612930338a3ff293967d6,file,620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e,620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e,620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e,True,True,7,2021-11-16T03:39:56Z,2022-08-05T08:37:26Z,2022-08-01T08:37:25Z,,1,1,1,1,5,8,,,
570c18ccf35a7003789f4332cb63bfce,fqdn,jeithe7eijeefohch3qu.probes.site,jeithe7eijeefohch3qu.probes.site,jeithe7eijeefohch3qu.probes.site,True,True,11,2020-11-25T21:11:41Z,2021-05-09T05:53:40Z,,,,,12,,13,12,,,
736e1acf892a27598d65a52136122699,,ef3363dfe2515b826584ab53c4bb7812,ef3363dfe2515b826584ab53c4bb7812,,False,False,,,,,,,,,,,,,,
"#;
        let lookup_mock = mock("POST", "/mrti/threats/bulk-lookup/")
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
        extract_mock.assert();
        lookup_mock.assert();

        assert_eq!(lookup_result, csv_body);
    }

    #[test]
    fn test_bulk_lookup_on_a_lot_of_values() {
        // Emulate a lot of values by reducing the size of chunks
        let mut setting = DatalakeSetting::prod();
        setting.bulk_lookup_chunk_size = 3;
        setting.set_base_url(mockito::server_url());
        let mut custom_dtl = Datalake::new(
            Some("username".to_string()),
            Some("password".to_string()),
            None,
            setting,
        );

        let atom_values = vec![
            "620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e",
            "jeithe7eijeefohch3qu.probes.site",
            "ef3363dfe2515b826584ab53c4bb7812",  // <- end of first chunk
            "probes.site",
            "probes2.site",
            "probes3.site", // <- end of second chunk
            "probes4.site",  // <- third chunk
        ];
        let atom_values_string: Vec<String> = atom_values.iter().map(|x| x.to_string()).collect();

        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let extract_mock_1 = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({
                "content":"620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e jeithe7eijeefohch3qu.probes.site ef3363dfe2515b826584ab53c4bb7812",
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
        let extract_mock_2 = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({
                "content":"probes.site probes2.site probes3.site",
                "treat_hashes_like": "file",
            })))
            .with_status(200)
            .with_body(json!({
                "found": 1,
                "not_found": [],
                "results": {
                    "domain": [
                        "probes.site",
                        "probes2.site",
                        "probes3.site",
                    ],
                }
            }).to_string())
            .create();
        let extract_mock_3 = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({
                "content":"probes4.site",
                "treat_hashes_like": "file",
            })))
            .with_status(200)
            .with_body(json!({
                "found": 1,
                "not_found": [],
                "results": {
                    "domain": [
                        "probes4.site",
                    ],
                }
            }).to_string())
            .create();
        let csv_body_1 = "hashkey,atom_type\n000001a049b612930338a3ff293967d6,file\n\
        570c18ccf35a7003789f4332cb63bfce,fqdn\n736e1acf892a27598d65a52136122699,\n";
        let lookup_mock_1 = mock("POST", "/mrti/threats/bulk-lookup/")
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
            .with_body(csv_body_1)
            .create();

        let csv_content_2 = "csv_content_2";
        let csv_header = r#"hashkey,atom_type,search_phrase,atom_value,atom_value_best_matching,threat_found,access_permission,events_number,first_seen,last_updated,last_updated_by_source,threat_types,ddos.score.risk,fraud.score.risk,hack.score.risk,leak.score.risk,malware.score.risk,phishing.score.risk,scam.score.risk,scan.score.risk,spam.score.risk,sources,tags,subcategories,href_graph,href_history,href_threat,href_threat_webGUI"#;
        let lookup_mock_2 = mock("POST", "/mrti/threats/bulk-lookup/")
            .match_body(Json(json!({
                    "hashkey_only": false,
                    "domain": [
                        "probes.site",
                        "probes2.site",
                        "probes3.site",
                    ]
                }))
            )
            .with_status(200)
            .with_body(&[csv_header, csv_content_2].join("\n"))
            .create();
        let csv_content_3 = "csv_content_3";
        let lookup_mock_3 = mock("POST", "/mrti/threats/bulk-lookup/")
            .match_body(Json(json!({
                    "hashkey_only": false,
                    "domain": [
                        "probes4.site",
                    ]
                }))
            )
            .with_status(200)
            .with_body(&[csv_header, csv_content_3].join("\n"))
            .create();

        let lookup_result = custom_dtl.bulk_lookup(atom_values_string, "file").unwrap();

        token_mock.assert();
        extract_mock_1.assert();
        lookup_mock_1.assert();
        extract_mock_2.assert();
        lookup_mock_2.assert();
        extract_mock_3.assert();
        lookup_mock_3.assert();

        let combined_csv = [
            "hashkey,atom_type",
            "000001a049b612930338a3ff293967d6,file",
            "570c18ccf35a7003789f4332cb63bfce,fqdn",
            "736e1acf892a27598d65a52136122699,",
            "csv_content_2",
            "csv_content_3",
            "",  // Make sure a new line is inserted at the end
        ].join("\n");
        assert_eq!(lookup_result, combined_csv);
    }

    #[test]
    fn test_bulk_lookup_on_a_lot_of_values_return_invalid_csv() {
        // Emulate a lot of values by reducing the size of chunks
        let mut setting = DatalakeSetting::prod();
        setting.bulk_lookup_chunk_size = 3;
        setting.set_base_url(mockito::server_url());
        let mut custom_dtl = Datalake::new(
            Some("username".to_string()),
            Some("password".to_string()),
            None,
            setting,
        );

        let atom_values = vec![
            "620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e",
            "jeithe7eijeefohch3qu.probes.site",
            "ef3363dfe2515b826584ab53c4bb7812",
            "probes.site",
        ];
        let atom_values_string: Vec<String> = atom_values.iter().map(|x| x.to_string()).collect();

        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let extract_mock_1 = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({
                "content":"620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e jeithe7eijeefohch3qu.probes.site ef3363dfe2515b826584ab53c4bb7812",
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
        let extract_mock_2 = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({
                "content":"probes.site",
                "treat_hashes_like": "file",
            })))
            .with_status(200)
            .with_body(json!({
                "found": 1,
                "not_found": [],
                "results": {
                    "domain": [
                        "probes.site",
                    ],
                }
            }).to_string())
            .create();
        let csv_body_1 = r#"hashkey,atom_type,search_phrase,atom_value,atom_value_best_matching,threat_found,access_permission,events_number,first_seen,last_updated,last_updated_by_source,threat_types,ddos.score.risk,fraud.score.risk,hack.score.risk,leak.score.risk,malware.score.risk,phishing.score.risk,scam.score.risk,scan.score.risk,spam.score.risk
000001a049b612930338a3ff293967d6,file,620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e,620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e,620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e,True,True,7,2021-11-16T03:39:56Z,2022-08-05T08:37:26Z,2022-08-01T08:37:25Z,,1,1,1,1,5,8,,,
570c18ccf35a7003789f4332cb63bfce,fqdn,jeithe7eijeefohch3qu.probes.site,jeithe7eijeefohch3qu.probes.site,jeithe7eijeefohch3qu.probes.site,True,True,11,2020-11-25T21:11:41Z,2021-05-09T05:53:40Z,,,,,12,,13,12,,,
736e1acf892a27598d65a52136122699,,ef3363dfe2515b826584ab53c4bb7812,ef3363dfe2515b826584ab53c4bb7812,,False,False,,,,,,,,,,,,,,
"#;
        let lookup_mock_1 = mock("POST", "/mrti/threats/bulk-lookup/")
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
            .with_body(csv_body_1)
            .create();

        let incorrect_csv_returned = r#"csv without carriage return"#;
        let lookup_mock_2 = mock("POST", "/mrti/threats/bulk-lookup/")
            .match_body(Json(json!({
                    "hashkey_only": false,
                    "domain": [
                        "probes.site",
                    ]
                }))
            )
            .with_status(200)
            .with_body(incorrect_csv_returned)
            .create();

        let error = custom_dtl.bulk_lookup(atom_values_string, "file").err().unwrap();
        assert_eq!(error.to_string(), "API Error unexpected csv result, missing body".to_string());
        match error {
            ApiError(details) => {
                assert_eq!(details.api_response, Some(incorrect_csv_returned.to_string()));
            }
            _ => { panic!() }
        }

        token_mock.assert();
        extract_mock_1.assert();
        lookup_mock_1.assert();
        extract_mock_2.assert();
        lookup_mock_2.assert();
    }

    #[test]
    fn test_bulk_lookup_error() {
        let atom_values = vec![
            "620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e",
            "ef3363dfe2515b826584ab53c4bb7812",
            "jeithe7eijeefohch3qu.probes.site",
        ];
        let atom_values_string: Vec<String> = atom_values.iter().map(|x| x.to_string()).collect();
        let api_response = r#"{"message":"Wrong credentials provided"}"#;

        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let api_status_code: u16 = 429;
        let extract_mock = mock("POST", "/mrti/threats/atom-values-extract/")
            .with_status(api_status_code as usize)
            .with_body(api_response)
            .create();
        let lookup_mock = mock("POST", "/mrti/threats/bulk-lookup/").create();
        let mut dtl = common::create_datalake();

        let err = dtl.bulk_lookup(atom_values_string, "file").err().unwrap();
        assert_eq!(err.to_string(), format!("API Error extracted API response not as expected"));
        if let ApiError(detailed_err) = err {
            assert_eq!(detailed_err.api_response.unwrap(), api_response);
            assert_eq!(detailed_err.api_status_code.unwrap(), StatusCode::from_u16(api_status_code).unwrap());
        } else {
            panic!("Unexpected error!")
        }

        token_mock.assert();
        extract_mock.assert();
        lookup_mock.expect_at_most(0).assert();  // Lookup is not called if extract failed
    }
}