#[path = "common.rs"]
mod common;

#[cfg(test)]
mod tests {
    use mockito::Matcher::Json;
    use mockito::mock;
    use reqwest::StatusCode;
    use serde_json::json;

    use ocd_datalake_rs::bulk_search::{BulkSearchTask, create_bulk_search_task, download_bulk_search, get_bulk_search_task};
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

        let task_uuid = create_bulk_search_task(
            &mut dtl,
            query_hash.clone(),
            query_fields.clone(),
        ).unwrap();

        token_mock.assert();
        bulk_search_mock.assert();

        assert_eq!(task_uuid, task_uid_returned);
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

    #[test]
    fn test_bulk_search_get_task() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let task_uid = "task_uuid123";
        let created_at = "2022-08-22T07:11:32.011836+00:00";
        let started_at = "2022-08-22T07:11:56.673034+00:00";
        let finished_at = "2022-08-22T07:11:57.797385+00:00";
        let state = "DONE";
        let results_number = 2;
        let bulk_search_task_mock = mock("POST", "/mrti/bulk-search/tasks/")
            .match_body(Json(json!({
                    "task_uuid": task_uid,
                }))
            )
            .with_status(200)
            .with_body(json!({
                 "count": 1,
                 "results": [{
                     "bulk_search_hash": "0ff239b3dd01cec5cd8343a7e9f1ae84",
                     "created_at": created_at,
                     "eta": null,
                     "file_delete_after": "2022-08-25T07:11:57.797385+00:00",
                     "file_deleted": false,  // Some extra fields are present but not yet saved
                     "file_size": 252,
                     "finished_at": finished_at,
                     "progress": null,
                     "queue_position": null,
                     "results": results_number,
                     "started_at": started_at,
                     "state": state,
                     "uuid": task_uid,
                 }]
            }).to_string())
            .create();
        let mut dtl = common::create_datalake();

        let task_created = get_bulk_search_task(
            &mut dtl,
            task_uid.to_string(),
        ).unwrap();

        token_mock.assert();
        bulk_search_task_mock.assert();

        let expected_task = BulkSearchTask {
            created_at: created_at.to_string(),
            started_at: started_at.to_string(),
            finished_at: finished_at.to_string(),
            queue_position: None,
            results: results_number,
            state: state.to_string(),
            uuid: task_uid.to_string(),
        };
        assert_eq!(task_created, expected_task)
    }

    #[test]
    fn test_bulk_search_get_task_on_error() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let task_uid = "task_uuid123";
        let bulk_search_task_mock = mock("POST", "/mrti/bulk-search/tasks/")
            .match_body(Json(json!({
                    "task_uuid": task_uid,
                }))
            )
            .with_status(200)
            .with_body(json!({ "unexpected json": true }).to_string())
            .create();
        let mut dtl = common::create_datalake();

        let error = get_bulk_search_task(&mut dtl, task_uid.to_string()).err().unwrap();

        token_mock.assert();
        bulk_search_task_mock.assert();

        assert_eq!(error.to_string(), "API Error bulk search task API response not as expected".to_string())
    }

    #[test]
    fn test_bulk_search_download() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let task_uid = "task_uuid123";
        let bulk_search_response_expected = json!({ "result": "some bulk search" }).to_string();  // TODO to csv
        let bulk_search_task_mock = mock("GET", format!("/mrti/bulk-search/tasks/{task_uid}").as_str())
            .match_header("Authorization", "Token 123")
            .match_header("Accept", "text/csv")
            .with_status(200)
            .with_body(bulk_search_response_expected.clone())
            .create();
        let mut dtl = common::create_datalake();

        let bulk_search_response = download_bulk_search(&mut dtl, task_uid.to_string()).unwrap();

        token_mock.assert();
        bulk_search_task_mock.assert();
        assert_eq!(bulk_search_response, bulk_search_response_expected)
    }

    #[test]
    fn test_bulk_search_download_on_not_ready_task() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let task_uid = "task_uuid123";
        let bulk_search_task_mock = mock("GET", format!("/mrti/bulk-search/tasks/{task_uid}").as_str())
            .with_status(202)  // 202 means not ready
            .with_body("bulk search is not ready")
            .create();
        let mut dtl = common::create_datalake();

        let error = download_bulk_search(&mut dtl, task_uid.to_string()).err().unwrap();

        token_mock.assert();
        bulk_search_task_mock.assert();
        assert_eq!(error.to_string(), format!("API Error bulk search with task uuid: {task_uid} is not ready to be downloaded"));
    }
}