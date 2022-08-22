use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use crate::{ApiError, Datalake, DatalakeError, DetailedError};

type TaskUuid = String;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct BulkSearchTask {
    pub created_at: String,
    pub started_at: String,
    pub finished_at: String,
    pub queue_position: Option<i64>,
    pub results: i64,
    pub state: String,
    pub uuid: TaskUuid,
}

/// Create a bulk search task and return its task_uuid
pub fn create_bulk_search_task(dtl: &mut Datalake, query_hash: String, query_fields: Vec<String>) -> Result<TaskUuid, DatalakeError> {
    let url = dtl.settings.routes().bulk_search.clone();

    let mut body = Map::new();
    body.insert("query_hash".to_string(), Value::String(query_hash));
    let query_fields_serialized = Value::Array(query_fields.into_iter().map(Value::String).collect());
    body.insert("query_fields".to_string(), query_fields_serialized);

    //
    let request = dtl.client.post(&url)
        .header("Authorization", dtl.get_token()?)
        .header("Accept", "text/csv");
    let resp = request.json(&body).send()?;

    // Prepare fields for error message
    let status_code = resp.status();
    let json_response = resp.json::<Value>()?;
    let api_response = Some(json_response.to_string());

    fn parse_json_response(json_resp: &Value) -> Option<String> {
        Some(json_resp.as_object()?.get("task_uuid")?.as_str()?.to_string())
    }

    match parse_json_response(&json_response) {
        Some(task) => { Ok(task) }
        None => {
            let err = DetailedError {
                summary: "bulk search API response not as expected".to_string(),
                api_url: Some(url),
                api_response,
                api_status_code: Some(status_code),
            };
            Err(ApiError(err))
        }
    }
}

/// Retrieve a bulk search task from a uuid
pub fn get_bulk_search_task(dtl: &mut Datalake, uuid: TaskUuid) -> Result<BulkSearchTask, DatalakeError> {
    let url = dtl.settings.routes().bulk_search_task.clone();
    let mut body = Map::new();
    body.insert("task_uuid".to_string(), Value::String(uuid));

    let request = dtl.client.post(&url)
        .header("Authorization", dtl.get_token()?)
        .header("Accept", "application/json");
    let resp = request.json(&body).send()?;

    // Prepare fields for error message
    let status_code = resp.status();
    let json_response = resp.json::<Value>()?;
    let api_response = Some(json_response.to_string());

    fn parse_json_response(json_resp: Value) -> Option<Value> {
        json_resp.as_object()?.get("results")?.get(0).cloned()
    }

    let bulk_search_task = match parse_json_response(json_response) {
        None => {
            let err = DetailedError {
                summary: "bulk search task API response not as expected".to_string(),
                api_url: Some(url),
                api_response,
                api_status_code: Some(status_code),
            };
            return Err(ApiError(err));
        }
        Some(task) => serde_json::from_value::<BulkSearchTask>(task)
    };
    match bulk_search_task {
        Ok(task) => { Ok(task) }
        Err(_) => {
            let err = DetailedError {
                summary: "bulk search task API response not as expected".to_string(),  // TODO
                api_url: Some(url),
                api_response,
                api_status_code: Some(status_code),
            };
            Err(ApiError(err))
        }
    }
}

