use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use crate::{ApiError, Datalake, DatalakeError, DetailedError};


#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct BulkSearchTask {
    pub bulk_search_hash: String,
    pub for_stix_export: bool,
    pub query_fields: Vec<String>,
    pub query_hash: String,
    pub task_uuid: String,
}

pub fn create_bulk_search_task(dtl: &mut Datalake, query_hash: String, query_fields: Vec<String>) -> Result<BulkSearchTask, DatalakeError> {
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
    let json_resp = resp.json::<Value>()?;
    let api_response = Some(json_resp.to_string());

    match serde_json::from_value(json_resp) {
        Ok(task) => { Ok(task) }
        Err(_) => {
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
