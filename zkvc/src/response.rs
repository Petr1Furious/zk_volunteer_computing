use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum VerificationResponse {
    Valid {
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<Vec<String>>,
    },
    Invalid {
        reason: String,
    },
    Error {
        error: String,
    },
}
