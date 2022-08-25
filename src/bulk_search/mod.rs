use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use crate::{ApiError, Datalake, DatalakeError, DetailedError};
use strum_macros::{EnumString, Display};
use std::str::FromStr;

type TaskUuid = String;

#[allow(non_camel_case_types)]
#[derive(Debug, Display, PartialEq, Eq, EnumString)]
pub enum State {
    NEW,
    QUEUED,
    IN_PROGRESS,
    DONE,
    CANCELLED,
    FAILED_ERROR,
    FAILED_TIMEOUT,
}


#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct BulkSearchTask {
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub queue_position: Option<i64>,
    pub results: Option<i64>,
    pub state: String,
    pub uuid: TaskUuid,
}

impl BulkSearchTask {
    pub fn get_state(&self) -> Result<State, DatalakeError> {
        match State::from_str(&self.state) {
            Ok(state) => Ok(state),
            Err(_) => {
                let error_summary = format!("Bulk search is in unexpected state: {}", self.state);
                Err(ApiError(DetailedError::new(error_summary)))
            }
        }
    }
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

    // Prepare an error if the received json is not a BulkSearchTask
    let summary = "bulk search task API response not as expected".to_string();
    let err = DetailedError { summary, api_url: Some(url), api_response, api_status_code: Some(status_code) };
    let api_error = Err(ApiError(err));

    match parse_json_response(json_response) {
        Some(task) => {
            match serde_json::from_value::<BulkSearchTask>(task) {
                Ok(task) => Ok(task),
                Err(_) => api_error,
            }
        }
        None => api_error,
    }
}

/// Retrieve a bulk search result from a task.
/// > **Warning** task must be in DONE state to be downloaded successfully
pub fn download_bulk_search(dtl: &mut Datalake, uuid: TaskUuid) -> Result<String, DatalakeError> {
    let url = dtl.settings.routes().bulk_search_download.replace("{task_uuid}", &uuid);
    let request = dtl.client.get(&url)
        .header("Authorization", dtl.get_token()?)
        .header("Accept", "text/csv");
    let resp = request.send()?;
    let status_code = resp.status();

    if status_code == 202 {
        let err = DetailedError {
            summary: format!("bulk search with task uuid: {uuid} is not ready to be downloaded"),
            api_url: Some(url),
            api_response: match resp.text() {
                Ok(r) => Some(r),
                Err(_) => None
            },
            api_status_code: Some(status_code),
        };
        return Err(ApiError(err));
    }
    if resp.error_for_status_ref().is_err() {
        let err = DetailedError {
            summary: format!("bulk search with task uuid: {uuid} returned error code {status_code}"),
            api_url: Some(url),
            api_response: match resp.text() {
                Ok(r) => Some(r),
                Err(_) => None
            },
            api_status_code: Some(status_code),
        };
        return Err(ApiError(err));
    }
    Ok(resp.text()?)
}

