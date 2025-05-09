use crate::{
    circuit::{ConstraintGenerator, ProofRequest, ZkCircuit},
    utils::field_to_string,
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{ProvingKey, create_random_proof};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::thread_rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

pub fn generate_proof_request(
    generator: Box<dyn ConstraintGenerator<Fr>>,
    pk: &ProvingKey<Bls12_381>,
) -> Result<ProofRequest, anyhow::Error> {
    let public_inputs: Arc<Mutex<Vec<Fr>>> = Arc::new(Mutex::new(vec![]));
    let circuit = ZkCircuit {
        generator,
        public_inputs: Arc::clone(&public_inputs),
    };

    let mut rng = thread_rng();
    let proof = create_random_proof::<Bls12_381, _, _>(circuit, &pk, &mut rng)?;

    let mut proof_bytes = vec![];
    proof.serialize_uncompressed(&mut proof_bytes)?;
    let proof = STANDARD.encode(&proof_bytes);

    let public_inputs = public_inputs.lock().unwrap();

    let public_inputs: Vec<String> = public_inputs
        .iter()
        .map(|&input| field_to_string(input))
        .collect();

    Ok(ProofRequest {
        proof,
        public_inputs,
    })
}

pub fn save_proof_request(request: &ProofRequest, file_path: &str) -> Result<(), anyhow::Error> {
    let json = serde_json::to_string(request)?;
    std::fs::write(file_path, json)?;
    Ok(())
}

pub fn load_proof_request(file_path: &str) -> Result<ProofRequest, anyhow::Error> {
    let json = std::fs::read_to_string(file_path)?;
    let request: ProofRequest = serde_json::from_str(&json)?;
    Ok(request)
}

pub fn load_proving_key(pk_path: &str) -> Result<ProvingKey<Bls12_381>, anyhow::Error> {
    let pk_bytes = std::fs::read(pk_path)?;
    let pk = ProvingKey::deserialize_uncompressed(&*pk_bytes)?;
    Ok(pk)
}

pub async fn send_proof_to_server(
    server_url: &str,
    request: ProofRequest,
) -> Result<String, anyhow::Error> {
    let client = Client::new();
    let resp = client
        .post(format!("{}/verify", server_url))
        .json(&request)
        .send()
        .await?;

    Ok(resp.text().await?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_url: String,
    pub proving_key_path: String,
    pub proof_path: String,
}

pub struct ClientApp {
    config: ClientConfig,
    proving_key: Option<ProvingKey<Bls12_381>>,
}

impl ClientApp {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            proving_key: None,
        }
    }

    pub fn load_proving_key(&mut self) -> Result<(), anyhow::Error> {
        self.proving_key = Some(load_proving_key(&self.config.proving_key_path)?);
        Ok(())
    }

    pub fn generate_proof(
        &self,
        generator: Box<dyn ConstraintGenerator<Fr>>,
    ) -> Result<ProofRequest, anyhow::Error> {
        let pk = self.proving_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Proving key not loaded. Call load_proving_key first.")
        })?;

        generate_proof_request(generator, pk)
    }

    pub fn save_proof(&self, request: &ProofRequest) -> Result<(), anyhow::Error> {
        save_proof_request(request, &self.config.proof_path)
    }

    pub async fn send_proof(&self, request: ProofRequest) -> Result<String, anyhow::Error> {
        send_proof_to_server(&self.config.server_url, request).await
    }
}
