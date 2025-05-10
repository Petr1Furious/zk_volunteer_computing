use actix_web::{web, App, HttpResponse, HttpServer};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{circuit::ProofRequest, utils::field_from_string};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_address: String,
    pub verification_key_path: String,
}

pub struct ServerApp {
    config: ServerConfig,
    verification_key: Arc<VerifyingKey<Bls12_381>>,
}

impl ServerApp {
    pub fn new(config: ServerConfig) -> Result<Self, anyhow::Error> {
        debug!("Creating new ServerApp instance");
        let vk_bytes = std::fs::read(&config.verification_key_path)?;
        let vk = VerifyingKey::deserialize_uncompressed(&*vk_bytes)?;
        info!("Verification key loaded successfully");

        Ok(Self {
            config,
            verification_key: Arc::new(vk),
        })
    }

    fn verify(&self, request: &ProofRequest) -> Result<bool, anyhow::Error> {
        debug!("Verifying proof");
        let proof_bytes = STANDARD.decode(&request.proof)?;
        let proof: Proof<Bls12_381> = Proof::deserialize_uncompressed(&*proof_bytes)?;
        let inputs: Vec<Fr> = request
            .public_inputs
            .iter()
            .map(|s| field_from_string(s))
            .collect::<Result<Vec<_>, _>>()?;
        debug!("Inputs: {:?}", inputs);

        let result = Groth16::<Bls12_381>::verify(&self.verification_key, &inputs, &proof)?;
        info!("Proof verification result: {}", result);
        Ok(result)
    }

    async fn verify_handler(
        request: web::Json<ProofRequest>,
        app: web::Data<Arc<Self>>,
    ) -> HttpResponse {
        debug!("Received verification request");
        match app.verify(&request) {
            Ok(true) => {
                info!("Proof verified successfully");
                HttpResponse::Ok().body("Proof is valid")
            }
            Ok(false) => {
                warn!("Invalid proof received");
                HttpResponse::BadRequest().body("Invalid proof")
            }
            Err(e) => {
                error!("Verification error: {}", e);
                HttpResponse::InternalServerError().body(format!("Verification error: {}", e))
            }
        }
    }

    pub async fn run_server(self) -> std::io::Result<()> {
        let address = self.config.listen_address.clone();
        info!("Starting server on {}", address);

        let app = Arc::new(self);
        HttpServer::new(move || {
            let app = web::Data::new(Arc::clone(&app));
            App::new()
                .app_data(app)
                .route("/verify", web::post().to(Self::verify_handler))
        })
        .bind(address)?
        .run()
        .await
    }

    pub fn get_listen_address(&self) -> &str {
        &self.config.listen_address
    }
}
