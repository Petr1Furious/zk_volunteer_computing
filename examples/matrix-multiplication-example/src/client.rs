use anyhow::Result;
use log::info;
use zkvc::client::{ClientApp, ClientConfig};
use zkvc::response::VerificationResponse;

use crate::circuit::MatrixMultiplicationCircuit;

pub struct MatrixMultiplicationClient {
    server_url: String,
    challenge_url: String,
    client_id: String,
    private_matrix: Vec<Vec<u64>>,
}

impl MatrixMultiplicationClient {
    pub fn new(
        server_url: String,
        challenge_url: String,
        client_id: String,
        private_matrix: Vec<Vec<u64>>,
    ) -> Self {
        Self {
            server_url,
            challenge_url,
            client_id,
            private_matrix,
        }
    }

    pub async fn run(&self) -> Result<()> {
        info!("Starting matrix multiplication client {}", self.client_id);

        info!("Requesting challenge from {}", self.challenge_url);
        let client = reqwest::Client::new();
        let response = client.get(&self.challenge_url).send().await?;
        let challenge: crate::challenge::ChallengeResponse = response.json().await?;

        let vector = challenge.vector;
        info!("Received challenge vector: {:?}", vector);

        let m = self.private_matrix[0].len();

        if vector.len() != m {
            return Err(anyhow::anyhow!(
                "Vector size {} does not match matrix width {}",
                vector.len(),
                m
            ));
        }

        let config = ClientConfig {
            server_url: self.server_url.clone(),
            proving_key_path: "mpk.bin".to_string(),
            proof_path: Some("matrix_proof.json".to_string()),
            client_id: self.client_id.clone(),
        };

        let client = ClientApp::new(config)?;

        let circuit = MatrixMultiplicationCircuit::new(self.private_matrix.clone(), vector);

        info!(
            "Client {} generating proof for matrix multiplication",
            self.client_id
        );

        let response = client.generate_and_send_proof(Box::new(circuit)).await?;
        match response {
            VerificationResponse::Valid { result } => {
                info!("Proof is valid! Server verified the zero-knowledge proof.");
                if let Some(res_inputs) = result {
                    info!("Public inputs from verified proof: {:?}", res_inputs);
                }
            }
            VerificationResponse::Invalid { reason } => {
                info!("Invalid proof: {}", reason);
            }
            VerificationResponse::Error { error } => {
                info!("Error during proof verification: {}", error);
            }
        }

        Ok(())
    }
}
