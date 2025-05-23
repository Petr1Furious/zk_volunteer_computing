use actix_web::{web, App, HttpResponse, HttpServer};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc, time::Instant};

use crate::{
    circuit::ProofRequest,
    response::VerificationResponse,
    utils::{field_from_string, VERIFY_PATH},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_address: String,
    pub verification_key_path: PathBuf,
}

pub struct ServerApp<VP, IP, EP>
where
    VP: Fn(&str, &[Fr]) -> Result<(), anyhow::Error> + Send + Sync + 'static,
    IP: Fn(&str, &str) -> Result<(), anyhow::Error> + Send + Sync + 'static,
    EP: Fn(&str, &anyhow::Error) -> Result<(), anyhow::Error> + Send + Sync + 'static,
{
    config: ServerConfig,
    verification_key: Arc<VerifyingKey<Bls12_381>>,
    valid_proof_handler: Option<VP>,
    invalid_proof_handler: Option<IP>,
    error_handler: Option<EP>,
}

impl<VP, IP, EP> ServerApp<VP, IP, EP>
where
    VP: Fn(&str, &[Fr]) -> Result<(), anyhow::Error> + Send + Sync + 'static,
    IP: Fn(&str, &str) -> Result<(), anyhow::Error> + Send + Sync + 'static,
    EP: Fn(&str, &anyhow::Error) -> Result<(), anyhow::Error> + Send + Sync + 'static,
{
    pub fn new(config: ServerConfig) -> Result<Self, anyhow::Error> {
        debug!("Creating new ServerApp instance");
        let start = Instant::now();
        let vk_bytes = std::fs::read(&config.verification_key_path)?;
        let vk = VerifyingKey::deserialize_unchecked(&*vk_bytes)?;
        info!(
            "Verification key loaded successfully in {:?}",
            start.elapsed()
        );

        Ok(Self {
            config,
            verification_key: Arc::new(vk),
            valid_proof_handler: None,
            invalid_proof_handler: None,
            error_handler: None,
        })
    }

    pub fn with_valid_proof_handler(mut self, handler: VP) -> Self {
        self.valid_proof_handler = Some(handler);
        self
    }

    pub fn with_invalid_proof_handler(mut self, handler: IP) -> Self {
        self.invalid_proof_handler = Some(handler);
        self
    }

    pub fn with_error_handler(mut self, handler: EP) -> Self {
        self.error_handler = Some(handler);
        self
    }

    fn verify(&self, request: &ProofRequest) -> Result<bool, anyhow::Error> {
        debug!("Verifying proof");
        let start = Instant::now();

        let proof_bytes = STANDARD.decode(&request.proof.0)?;
        let proof: Proof<Bls12_381> = Proof::deserialize_uncompressed(&*proof_bytes)?;
        let inputs: Vec<Fr> = request
            .public_inputs
            .iter()
            .map(|s| field_from_string(s))
            .collect::<Result<Vec<_>, _>>()?;
        debug!("Inputs: {:?}", inputs);

        let result = Groth16::<Bls12_381>::verify(&self.verification_key, &inputs, &proof)?;
        debug!("Proof verification completed in {:?}", start.elapsed());
        info!("Proof verification result: {}", result);
        Ok(result)
    }

    async fn verify_handler(
        request: web::Json<ProofRequest>,
        app: web::Data<Arc<Self>>,
    ) -> HttpResponse {
        let start = Instant::now();
        debug!(
            "Received verification request from client {}",
            request.client_id
        );

        let inputs: Vec<Fr> = match request
            .public_inputs
            .iter()
            .map(|s| field_from_string(s))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(inputs) => inputs,
            Err(e) => {
                error!("Failed to parse inputs: {}", e);
                if let Some(handler) = &app.error_handler {
                    if let Err(handler_err) = handler(&request.client_id, &e) {
                        error!("Error handler failed: {}", handler_err);
                    }
                }
                return HttpResponse::InternalServerError().json(VerificationResponse::Error {
                    error: e.to_string(),
                });
            }
        };

        let response = match app.verify(&request) {
            Ok(true) => {
                info!(
                    "Proof verified successfully for client {}",
                    request.client_id
                );
                if let Some(handler) = &app.valid_proof_handler {
                    if let Err(e) = handler(&request.client_id, &inputs) {
                        error!("Valid proof handler failed: {}", e);
                        return HttpResponse::InternalServerError().json(
                            VerificationResponse::Error {
                                error: e.to_string(),
                            },
                        );
                    }
                }
                HttpResponse::Ok().json(VerificationResponse::Valid {
                    result: Some(request.public_inputs.clone()),
                })
            }
            Ok(false) => {
                warn!("Invalid proof received from client {}", request.client_id);
                let reason = "Proof verification failed".to_string();
                if let Some(handler) = &app.invalid_proof_handler {
                    if let Err(e) = handler(&request.client_id, &reason) {
                        error!("Invalid proof handler failed: {}", e);
                        return HttpResponse::InternalServerError().json(
                            VerificationResponse::Error {
                                error: e.to_string(),
                            },
                        );
                    }
                }
                HttpResponse::BadRequest().json(VerificationResponse::Invalid { reason })
            }
            Err(e) => {
                error!("Verification error for client {}: {}", request.client_id, e);
                if let Some(handler) = &app.error_handler {
                    if let Err(handler_err) = handler(&request.client_id, &e) {
                        error!("Error handler failed: {}", handler_err);
                    }
                }
                HttpResponse::InternalServerError().json(VerificationResponse::Error {
                    error: e.to_string(),
                })
            }
        };

        debug!("Total request handling time: {:?}", start.elapsed());
        response
    }

    pub async fn run(self) -> std::io::Result<()> {
        let address = self.config.listen_address.clone();
        info!("Starting server on {}", address);

        let app = Arc::new(self);
        HttpServer::new(move || {
            let app = web::Data::new(Arc::clone(&app));
            App::new()
                .app_data(app)
                .route(VERIFY_PATH, web::post().to(Self::verify_handler))
        })
        .bind(address)?
        .run()
        .await
    }

    pub fn get_listen_address(&self) -> &str {
        &self.config.listen_address
    }
}
