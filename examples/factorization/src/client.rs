use std::path::PathBuf;

use anyhow::Result;
use log::info;
use reqwest::Url;
use zkvc::client::{ClientApp, ClientConfig};
use zkvc::response::VerificationResponse;

use crate::circuit::FactorizationCircuit;

pub struct FactorizationClient {
    server_url: String,
    challenge_url: String,
    client_id: String,
}

impl FactorizationClient {
    pub fn new(server_url: String, challenge_url: String, client_id: String) -> Self {
        Self {
            server_url,
            challenge_url,
            client_id,
        }
    }

    pub async fn run(&self, p1: Option<u64>, p2: Option<u64>, product: Option<u64>) -> Result<()> {
        info!("Starting factorization client {}", self.client_id);

        let (p1, p2, product) = if let (Some(p1), Some(p2), Some(product)) = (p1, p2, product) {
            info!(
                "Using provided values: p1={}, p2={}, product={}",
                p1, p2, product
            );
            (p1, p2, product)
        } else {
            info!("Requesting challenge from {}", self.challenge_url);
            let client = reqwest::Client::new();
            let response = client.get(&self.challenge_url).send().await?;
            let challenge: crate::challenge::ChallengeResponse = response.json().await?;
            let product = challenge.product;
            info!("Received challenge: product={}", product);

            info!("Starting factorization...");
            let start = std::time::Instant::now();
            let factors = find_factors(product)
                .ok_or_else(|| anyhow::anyhow!("Failed to factorize {}", product))?;
            let elapsed = start.elapsed();
            info!(
                "Factorization completed in {:?}. Found factors: {} * {} = {}",
                elapsed, factors.0, factors.1, product
            );

            (factors.0, factors.1, product)
        };

        let config = ClientConfig {
            server_url: Url::parse(&self.server_url)?,
            proving_key_path: PathBuf::from("fpk.bin"),
            proof_path: Some(PathBuf::from("factor_proof.json")),
            client_id: self.client_id.clone(),
        };

        let client = ClientApp::new(config)?;

        let circuit = FactorizationCircuit { p1, p2, product };

        info!(
            "Client {} generating proof for p1={}, p2={}, product={}",
            self.client_id, p1, p2, product
        );

        let response = client.generate_and_send_proof(Box::new(circuit)).await?;
        match response {
            VerificationResponse::Valid { result } => {
                info!(
                    "Proof is valid! Server verified that client knows factors for {}.",
                    product
                );
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

fn find_factors(n: u64) -> Option<(u64, u64)> {
    let mut i = 2;
    while i * i <= n {
        if n % i == 0 {
            return Some((i, n / i));
        }
        i += 1;
    }
    None
}
