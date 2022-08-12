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
        let extract_mock = mock("POST", "/mrti/threats/atom-values-extract/")
            .match_body(Json(json!({"content":"domain.com 4.4.4.4 1.1.1.1"})))
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
            .match_body(Json(json!({"content":"123"})))
            .match_header("Authorization", "Token 123")
            .with_status(200)
            .with_body(r#"{"found":0,"not_found":["123"],"results":{}}"#)
            .create();
        let mut dtl = common::create_datalake();
        let atom_values = vec!["123".to_string()];

        let result = dtl.extract_atom_type(&atom_values);

        // Check mock called happened
        token_mock.assert();
        extract_mock.assert();

        assert!(result.is_empty());  // No result returned
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
                "content":"620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e ef3363dfe2515b826584ab53c4bb7812 jeithe7eijeefohch3qu.probes.site"
            })))
            .with_status(200)  // TODO test not found atom
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

        let lookup_result = dtl.bulk_lookup(atom_values_string);

        token_mock.assert();
        extract_mock.assert();
        lookup_mock.assert();

        assert_eq!(lookup_result, csv_body);
    }
}