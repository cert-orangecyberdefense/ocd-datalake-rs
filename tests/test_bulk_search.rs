#[path = "common.rs"]
mod common;

#[cfg(test)]
mod tests {
    use mockito::Matcher::Json;
    use mockito::mock;
    use reqwest::StatusCode;
    use serde_json::json;
    use rstest::rstest;

    use ocd_datalake_rs::bulk_search::{BulkSearchTask, create_bulk_search_task, download_bulk_search, get_bulk_search_task};
    use ocd_datalake_rs::error::DatalakeError::ApiError;
    use ocd_datalake_rs::error::DetailedError;

    use crate::common;

    #[test]
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
        let bulk_search_response_expected = "some bulk search csv result".to_string();
        let bulk_search_download_mock = mock("GET", format!("/mrti/bulk-search/task/{task_uid}").as_str())
            .match_header("Authorization", "Token 123")
            .match_header("Accept", "text/csv")
            .with_status(200)
            .with_body(bulk_search_response_expected.clone())
            .create();
        let mut dtl = common::create_datalake();

        let task_created = dtl.bulk_search(query_hash, query_fields).unwrap();

        token_mock.assert();
        bulk_search_mock.assert();
        bulk_search_task_mock.assert();  // TODO test with tasks having != state
        bulk_search_download_mock.assert();

        assert_eq!(task_created, bulk_search_response_expected);
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
            started_at: Some(started_at.to_string()),
            finished_at: Some(finished_at.to_string()),
            queue_position: None,
            results: Some(results_number),
            state: state.to_string(),
            uuid: task_uid.to_string(),
        };
        assert_eq!(task_created, expected_task)
    }

    #[test]
    /// The returned bulk search task has a lot of null fields as it was just created
    fn test_bulk_search_get_task_newly_created() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let bulk_search_task_mock = mock("POST", "/mrti/bulk-search/tasks/")
            .with_status(200)
            .with_body(json!({
                  "count": 1,
                  "results": [
                    {
                      "bulk_search": {
                        "advanced_query_hash": "fbecd3d440a7d439a2a1fd996c703a8d",
                        "for_stix_export": false,
                        "query_fields": [
                          "atom_value"
                        ]
                      },
                      "bulk_search_hash": "6b9708debe40c2b11932b0fa9ec0b134",
                      "created_at": "2022-08-24T06:54:39.420074+00:00",
                      "eta": "2022-08-24T06:54:40.760737+00:00",
                      "file_delete_after": null,
                      "file_deleted": false,
                      "file_size": null,
                      "finished_at": null,
                      "progress": 0,
                      "queue_position": null,
                      "results": null,
                      "started_at": null,
                      "state": "NEW",
                      "user": {
                        "email": "hugo.chastel@orange.com",
                        "full_name": "hugo chastel",
                        "id": 287,
                        "organization": {
                          "id": 12,
                          "name": "OCD",
                          "path_names": [
                            "OCD"
                          ]
                        }
                      },
                      "uuid": "61a5efff-b0c0-4d4d-b4fa-5d4d7611cce5"
                    }
                  ]
                }).to_string())
            .create();
        let mut dtl = common::create_datalake();

        let task_created = get_bulk_search_task(&mut dtl, "task_uid123".to_string()).unwrap();

        token_mock.assert();
        bulk_search_task_mock.assert();
        assert_eq!(task_created.state, "NEW")
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
        let bulk_search_response_expected = "some bulk search csv result".to_string();
        let bulk_search_task_mock = mock("GET", format!("/mrti/bulk-search/task/{task_uid}").as_str())
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
        let bulk_search_task_mock = mock("GET", format!("/mrti/bulk-search/task/{task_uid}").as_str())
            .with_status(202)  // 202 means not ready
            .with_body("bulk search is not ready")
            .create();
        let mut dtl = common::create_datalake();

        let error = download_bulk_search(&mut dtl, task_uid.to_string()).err().unwrap();

        token_mock.assert();
        bulk_search_task_mock.assert();
        assert_eq!(error.to_string(), format!("API Error bulk search with task uuid: {task_uid} is not ready to be downloaded"));
    }

    #[test]
    /// If return status code is 4xx or 5xx,
    fn test_bulk_search_download_on_not_expected_status_code() {
        let token_mock = mock("POST", "/auth/token/")
            .with_status(200)
            .with_body(r#"{"access_token": "123","refresh_token": "456"}"#)
            .create();
        let task_uid = "task_uuid123";
        let bulk_search_task_mock = mock("GET", format!("/mrti/bulk-search/task/{task_uid}").as_str())
            .with_status(404)
            .with_body("url not found")
            .create();
        let mut dtl = common::create_datalake();

        let error = download_bulk_search(&mut dtl, task_uid.to_string()).err().unwrap();

        token_mock.assert();
        bulk_search_task_mock.assert();
        assert_eq!(error.to_string(), format!("API Error bulk search with task uuid: {task_uid} returned error code 404 Not Found"));
    }

    #[rstest]
    #[case("NEW")]
    #[case("QUEUED")]
    #[case("IN_PROGRESS")]
    fn test_bulk_search_not_ready(#[case] not_ready_state: &str) {
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
        let task_uid = "task_uuid123";
        let created_at = "2022-08-22T07:11:32.011836+00:00";
        let started_at = "2022-08-22T07:11:56.673034+00:00";
        let finished_at = "2022-08-22T07:11:57.797385+00:00";
        let state = "DONE";
        let results_number = 2;
        let no_ready_state_mock = mock("POST", "/mrti/bulk-search/tasks/")
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
                     "finished_at": null,
                     "progress": null,
                     "queue_position": null,
                     "results": null,
                     "started_at": started_at,
                     "state": not_ready_state,
                     "uuid": task_uid,
                 }]
            }).to_string())
            .expect(2)  // stay in progress for 2 API call
            .create();
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
        let bulk_search_response_expected = "some bulk search csv result".to_string();
        let bulk_search_download_mock = mock("GET", format!("/mrti/bulk-search/task/{task_uid}").as_str())
            .match_header("Authorization", "Token 123")
            .match_header("Accept", "text/csv")
            .with_status(200)
            .with_body(bulk_search_response_expected.clone())
            .create();
        let mut dtl = common::create_datalake();

        let task_created = dtl.bulk_search(query_hash, query_fields).unwrap();

        token_mock.assert();
        bulk_search_mock.assert();
        bulk_search_task_mock.assert();
        no_ready_state_mock.assert();
        bulk_search_download_mock.assert();

        assert_eq!(task_created, bulk_search_response_expected);
    }

    #[rstest]
    #[case("CANCELLED")]
    #[case("FAILED_ERROR")]
    #[case("FAILED_TIMEOUT")]
    fn test_bulk_search_failed(#[case] error_state: &str) {
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
        let task_uid = "task_uuid123";
        let created_at = "2022-08-22T07:11:32.011836+00:00";
        let started_at = "2022-08-22T07:11:56.673034+00:00";
        let error_state_mock = mock("POST", "/mrti/bulk-search/tasks/")
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
                     "finished_at": null,
                     "progress": null,
                     "queue_position": null,
                     "results": null,
                     "started_at": started_at,
                     "state": error_state,
                     "uuid": task_uid,
                 }]
            }).to_string())
            .create();
        let bulk_search_download_mock = mock("GET", format!("/mrti/bulk-search/task/{task_uid}").as_str())
            .match_header("Authorization", "Token 123")
            .match_header("Accept", "text/csv")
            .with_status(200)
            .with_body("some body")
            .expect(0)  // Download should not be called
            .create();
        let mut dtl = common::create_datalake();

        let error = dtl.bulk_search(query_hash, query_fields).err().unwrap();

        token_mock.assert();
        bulk_search_mock.assert();
        error_state_mock.assert();
        bulk_search_download_mock.assert();

        assert_eq!(error.to_string(), format!("API Error Bulk search is in {error_state} state"));
    }
}