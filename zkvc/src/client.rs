use crate::{
    circuit::{ConstraintGenerator, ProofRequest, ZkCircuit},
    utils::field_to_string,
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{ProvingKey, create_random_proof};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use log::{debug, info, warn};
use rand::thread_rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

pub(crate) fn generate_proof_request(
    generator: Box<dyn ConstraintGenerator<Fr>>,
    pk: &ProvingKey<Bls12_381>,
) -> Result<ProofRequest, anyhow::Error> {
    debug!("Generating proof request");
    let public_inputs: Arc<Mutex<Vec<Fr>>> = Arc::new(Mutex::new(vec![]));
    let circuit = ZkCircuit {
        generator,
        public_inputs: Arc::clone(&public_inputs),
    };

    let mut rng = thread_rng();
    let proof = create_random_proof::<Bls12_381, _, _>(circuit, &pk, &mut rng)?;
    debug!("Proof generated successfully");

    let mut proof_bytes = vec![];
    proof.serialize_uncompressed(&mut proof_bytes)?;
    let proof = STANDARD.encode(&proof_bytes);
    debug!("Proof serialized and encoded");

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

pub(crate) fn save_proof_request(request: &ProofRequest, file_path: &str) -> Result<(), anyhow::Error> {
    debug!("Saving proof request to {}", file_path);
    let json = serde_json::to_string(request)?;
    std::fs::write(file_path, json)?;
    info!("Proof request saved successfully");
    Ok(())
}

pub(crate) fn load_proving_key(pk_path: &str) -> Result<ProvingKey<Bls12_381>, anyhow::Error> {
    debug!("Loading proving key from {}", pk_path);
    let pk_bytes = std::fs::read(pk_path)?;
    let pk = ProvingKey::deserialize_uncompressed(&*pk_bytes)?;
    info!("Proving key loaded successfully");
    Ok(pk)
}

pub(crate) async fn send_proof_to_server(
    server_url: &str,
    request: ProofRequest,
) -> Result<String, anyhow::Error> {
    debug!("Sending proof to server at {}", server_url);
    let client = Client::new();
    let resp = client
        .post(format!("{}/verify", server_url))
        .json(&request)
        .send()
        .await?;

    let response = resp.text().await?;
    info!("Received response from server");
    Ok(response)
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
        debug!("Creating new ClientApp instance");
        Self {
            config,
            proving_key: None,
        }
    }

    pub fn load_proving_key(&mut self) -> Result<(), anyhow::Error> {
        debug!("Loading proving key");
        self.proving_key = Some(load_proving_key(&self.config.proving_key_path)?);
        info!("Proving key loaded successfully");
        Ok(())
    }

    pub fn generate_proof(
        &self,
        generator: Box<dyn ConstraintGenerator<Fr>>,
    ) -> Result<ProofRequest, anyhow::Error> {
        debug!("Generating proof");
        let pk = self.proving_key.as_ref().ok_or_else(|| {
            warn!("Attempted to generate proof without loaded proving key");
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

    pub async fn generate_and_send_proof(
        &self,
        generator: Box<dyn ConstraintGenerator<Fr>>,
    ) -> Result<String, anyhow::Error> {
        debug!("Generating and sending proof");
        let proof_request = self.generate_proof(generator)?;
        self.save_proof(&proof_request)?;
        self.send_proof(proof_request).await
    }

    pub fn with_proving_key(mut self) -> Result<Self, anyhow::Error> {
        self.load_proving_key()?;
        Ok(self)
    }

    pub fn with_config(config: ClientConfig) -> Result<Self, anyhow::Error> {
        let mut app = Self::new(config);
        app.load_proving_key()?;
        Ok(app)
    }

    pub fn get_proof_path(&self) -> &str {
        &self.config.proof_path
    }

    pub fn get_server_url(&self) -> &str {
        &self.config.server_url
    }
}
