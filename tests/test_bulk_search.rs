#[path = "common.rs"]
mod common;

#[cfg(test)]
mod tests {
    use mockito::Matcher::Json;
    use mockito::mock;
    use reqwest::StatusCode;
    use serde_json::json;
    use ocd_datalake_rs::bulk_search::{BulkSearchTask, create_bulk_search_task};
    use ocd_datalake_rs::error::DatalakeError::ApiError;
    use ocd_datalake_rs::error::DetailedError;
    use crate::common;

    #[test]
    #[ignore]
    fn test_bulk_search() {
        let query_hash = "query_hash123".to_string();
        let query_fields = vec!["atom_value".to_string()];
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let bulk_search_mock = mock("POST", "/mrti/bulk-search/")
            .match_body(Json(json!({
                    "query_hash": query_hash,
                    "query_fields": query_fields,
                }))
            )
            .with_status(200)
            .with_body(json!({
                "bulk_search_hash": "0bac54db1a8bdc1371bd06a80a1334af",
                "for_stix_export": false,
                "query_fields": ["atom_value"],
                "query_hash": "query_hash123",
                "task_uuid": "task_uuid123"
            }).to_string())
            .create();
        let mut dtl = common::create_datalake();

        let task_created = dtl.bulk_search(query_hash, &query_fields).unwrap();

        token_mock.assert();
        bulk_search_mock.assert();

        assert_eq!(task_created, vec!["42".to_string()]);  // TODO
    }

    #[test]
    fn test_bulk_search_create_task() {
        let query_hash = "query_hash123".to_string();
        let query_fields = vec!["atom_value".to_string()];
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let task_uid_returned = "task_uuid123";
        let bulk_search_hash_returned = "0bac54db1a8bdc1371bd06a80a1334af";
        let bulk_search_mock = mock("POST", "/mrti/bulk-search/")
            .match_body(Json(json!({
                    "query_hash": query_hash,
                    "query_fields": query_fields,
                }))
            )
            .with_status(200)
            .with_body(json!({
                "bulk_search_hash": bulk_search_hash_returned,
                "for_stix_export": false,
                "query_fields": ["atom_value"],
                "query_hash": "query_hash123",
                "task_uuid": task_uid_returned
            }).to_string())
            .create();
        let mut dtl = common::create_datalake();

        let task_created = create_bulk_search_task(
            &mut dtl,
            query_hash.clone(),
            query_fields.clone(),
        ).unwrap();

        token_mock.assert();
        bulk_search_mock.assert();

        assert_eq!(task_created, BulkSearchTask {
            bulk_search_hash: bulk_search_hash_returned.to_string(),
            for_stix_export: false,
            query_fields,
            query_hash,
            task_uuid: task_uid_returned.to_string(),
        });
    }

    #[test]
    fn test_bulk_search_create_task_with_error_incorrect_result() {
        let query_hash = "query_hash123".to_string();
        let query_fields = vec!["atom_value".to_string()];
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let api_status_code = 412;
        let endpoint_path = "/mrti/bulk-search/";
        let bulk_search_mock = mock("POST", endpoint_path)
            .match_body(Json(json!({
                    "query_hash": query_hash,
                    "query_fields": query_fields,
                }))
            )
            .with_status(api_status_code)
            .with_body(json!({
                "msg": "error no one could have predicted"
            }).to_string())
            .create();
        let mut dtl = common::create_datalake();

        let error = create_bulk_search_task(
            &mut dtl,
            query_hash.clone(),
            query_fields.clone(),
        ).err().unwrap();

        token_mock.assert();
        bulk_search_mock.assert();

        let api_url = mockito::server_url() + endpoint_path;
        let expected_error = ApiError(DetailedError {
            summary: "bulk search API response not as expected".to_string(),
            api_url: Some(api_url),
            api_response: Some(json!({
                "msg": "error no one could have predicted"
            }).to_string()),
            api_status_code: Some(StatusCode::from_u16(api_status_code as u16).unwrap()),
        });

        assert_eq!(error, expected_error);
    }
}