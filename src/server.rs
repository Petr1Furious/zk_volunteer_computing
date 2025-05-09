use actix_web::{App, HttpResponse, HttpServer, web};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{circuit::ProofRequest, utils::field_from_string};

pub fn verify(request: &ProofRequest, vk: &VerifyingKey<Bls12_381>) -> Result<bool, anyhow::Error> {
    let proof_bytes = STANDARD.decode(&request.proof)?;
    let proof: Proof<Bls12_381> = Proof::deserialize_uncompressed(&*proof_bytes)?;
    let inputs: Vec<Fr> = request
        .public_inputs
        .iter()
        .map(|s| field_from_string(s))
        .collect::<Result<Vec<_>, _>>()?;
    println!("Inputs: {:?}", inputs);

    Ok(Groth16::<Bls12_381>::verify(vk, &inputs, &proof)?)
}

pub fn load_verification_key(vk_path: &str) -> Result<VerifyingKey<Bls12_381>, anyhow::Error> {
    let vk_bytes = std::fs::read(vk_path)?;
    let vk = VerifyingKey::deserialize_uncompressed(&*vk_bytes)?;
    Ok(vk)
}

pub fn verify_proof_from_file(
    proof_request_path: &str,
    vk_path: &str,
) -> Result<bool, anyhow::Error> {
    let vk = load_verification_key(vk_path)?;
    let json = std::fs::read_to_string(proof_request_path)?;
    let request: ProofRequest = serde_json::from_str(&json)?;
    verify(&request, &vk)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_address: String,
    pub verification_key_path: String,
}

pub struct ServerApp {
    config: ServerConfig,
    verification_key: Option<Arc<VerifyingKey<Bls12_381>>>,
}

async fn verify_handler(
    request: web::Json<ProofRequest>,
    vk: web::Data<Arc<VerifyingKey<Bls12_381>>>,
) -> HttpResponse {
    match verify(&request, &vk) {
        Ok(true) => HttpResponse::Ok().body("Proof is valid"),
        Ok(false) => HttpResponse::BadRequest().body("Invalid proof"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Verification error: {}", e)),
    }
}

impl ServerApp {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            verification_key: None,
        }
    }

    pub fn load_verification_key(&mut self) -> Result<(), anyhow::Error> {
        let vk = load_verification_key(&self.config.verification_key_path)?;
        self.verification_key = Some(Arc::new(vk));
        Ok(())
    }

    pub async fn run_server(self) -> std::io::Result<()> {
        let vk = self.verification_key.expect("Verification key not loaded");
        let address = self.config.listen_address.clone();

        println!("Starting server on {}", address);

        HttpServer::new(move || {
            let vk_data = web::Data::new(Arc::clone(&vk));

            App::new()
                .app_data(vk_data.clone())
                .route("/verify", web::post().to(verify_handler))
        })
        .bind(address)?
        .run()
        .await
    }
}
