use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub vector: Vec<u64>,
}
