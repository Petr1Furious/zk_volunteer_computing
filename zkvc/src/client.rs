use crate::{
    circuit::{Base64Proof, ConstraintGenerator, ProofRequest, ZkCircuit},
    response::VerificationResponse,
    utils::{field_to_string, VERIFY_PATH},
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{create_random_proof, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::{debug, info};
use rand::thread_rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_url: Url,
    pub proving_key_path: PathBuf,
    pub proof_path: Option<PathBuf>,
    pub client_id: String,
}

pub struct ClientApp {
    config: ClientConfig,
    proving_key: ProvingKey<Bls12_381>,
}

impl ClientApp {
    pub fn new(config: ClientConfig) -> Result<Self, anyhow::Error> {
        debug!("Creating new ClientApp instance");
        let pk_bytes = std::fs::read(&config.proving_key_path)?;
        let pk = ProvingKey::deserialize_uncompressed(&*pk_bytes)?;
        info!("Proving key loaded successfully");

        Ok(Self {
            config,
            proving_key: pk,
        })
    }

    fn generate_proof_request(
        &self,
        generator: Box<dyn ConstraintGenerator<Fr>>,
    ) -> Result<ProofRequest, anyhow::Error> {
        debug!("Generating proof request");
        let start = Instant::now();

        let public_inputs: Arc<Mutex<Vec<Fr>>> = Arc::new(Mutex::new(Vec::new()));
        let circuit = ZkCircuit {
            generator,
            public_inputs: Arc::clone(&public_inputs),
        };

        let mut rng = thread_rng();
        let proof = create_random_proof::<Bls12_381, _, _>(circuit, &self.proving_key, &mut rng)?;
        debug!("Proof generated successfully in {:?}", start.elapsed());

        let start_serialize = Instant::now();
        let mut proof_bytes = vec![];
        proof.serialize_uncompressed(&mut proof_bytes)?;
        let base64_proof = Base64Proof(STANDARD.encode(&proof_bytes));
        debug!(
            "Proof serialized and encoded in {:?}",
            start_serialize.elapsed()
        );

        let public_inputs = public_inputs.lock().unwrap();
        let public_inputs: Vec<String> = public_inputs
            .iter()
            .map(|&input| field_to_string(input))
            .collect();

        Ok(ProofRequest {
            client_id: self.config.client_id.clone(),
            proof: base64_proof,
            public_inputs,
        })
    }

    fn save_proof(&self, request: &ProofRequest) -> Result<(), anyhow::Error> {
        if let Some(path) = &self.config.proof_path {
            debug!("Saving proof request to {}", path.display());
            let json = serde_json::to_string(request)?;
            std::fs::write(path, json)?;
            info!("Proof request saved successfully");
        }
        Ok(())
    }

    async fn send_proof(
        &self,
        request: ProofRequest,
    ) -> Result<VerificationResponse, anyhow::Error> {
        debug!("Sending proof to server at {}", self.config.server_url);
        let start = Instant::now();

        let client = Client::new();
        let resp = client
            .post(self.config.server_url.join(VERIFY_PATH)?)
            .json(&request)
            .send()
            .await?;

        let response = resp.json::<VerificationResponse>().await?;
        debug!("Received response from server in {:?}", start.elapsed());
        Ok(response)
    }

    pub async fn generate_and_send_proof(
        &self,
        generator: Box<dyn ConstraintGenerator<Fr>>,
    ) -> Result<VerificationResponse, anyhow::Error> {
        debug!("Generating and sending proof");
        let proof_request = self.generate_proof_request(generator)?;
        self.save_proof(&proof_request)?;
        self.send_proof(proof_request).await
    }

    pub fn get_proof_path(&self) -> Option<&PathBuf> {
        self.config.proof_path.as_ref()
    }

    pub fn get_server_url(&self) -> &Url {
        &self.config.server_url
    }

    pub fn get_client_id(&self) -> &str {
        &self.config.client_id
    }
}
