use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub product: u64,
}
