use std::error::Error;
use std::fmt;
use reqwest::StatusCode;
use crate::DatalakeError::TimeoutError;
use crate::error::DatalakeError::{ApiError, AuthenticationError, HttpError, ParseError, UnexpectedLibError};

#[derive(Debug, PartialEq, Eq)]
pub struct DetailedError {
    pub summary: String,
    pub api_url: Option<String>,
    pub api_response: Option<String>,
    pub api_status_code: Option<StatusCode>,
}

impl DetailedError {
    pub fn new(summary: String) -> Self {
        DetailedError {
            summary,
            api_url: None,
            api_response: None,
            api_status_code: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DatalakeError {
    AuthenticationError(DetailedError),
    HttpError(DetailedError),
    ApiError(DetailedError),
    TimeoutError(DetailedError),
    ParseError(DetailedError),
    UnexpectedLibError(DetailedError),
}


impl fmt::Display for DetailedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.summary)
    }
}

impl fmt::Display for DatalakeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthenticationError(err) => write!(f, "Authentication Error {}", err),
            HttpError(err) => write!(f, "HTTP Error {}", err),
            TimeoutError(err) => write!(f, "Timeout Error {}", err),
            ApiError(err) => write!(f, "API Error {}", err),
            ParseError(err) => write!(f, "Parse Error {}", err),
            UnexpectedLibError(err) => write!(f, "Unexpected Library Error {}", err),
        }
    }
}

impl From<reqwest::Error> for DatalakeError {
    fn from(error: reqwest::Error) -> Self {
        let mut detailed_error = DetailedError {
            summary: error.to_string(),
            api_url: error.url().map(|u| u.to_string()),
            api_response: None,
            api_status_code: error.status(),
        };
        if error.is_decode() {
            return ParseError(detailed_error);
        }
        // default to http error
        let no_url_string = "<no url>".to_string();
        let url = detailed_error.api_url.as_ref().unwrap_or(&no_url_string);
        detailed_error.summary = format!("Could not fetch API for url {}", url);
        Self::HttpError(detailed_error)
    }
}

impl From<strum::ParseError> for DatalakeError {
    fn from(error: strum::ParseError) -> Self {
        let unexpected_state = error.source().unwrap().to_string();
        ApiError(DetailedError::new(format!("Bulk search is in unexpected state: {unexpected_state}")))
    }
}