use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use anyhow::Result;
use log::info;
use rand::Rng;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use zkvc::server::{ServerApp, ServerConfig};
use zkvc::utils;

pub struct MatrixMultiplicationServer {
    address: String,
    challenge_address: String,
    matrix_dimensions: (usize, usize),
}

impl MatrixMultiplicationServer {
    pub fn new(
        address: String,
        challenge_address: String,
        matrix_dimensions: (usize, usize),
    ) -> Self {
        Self {
            address,
            challenge_address,
            matrix_dimensions,
        }
    }

    pub async fn run(&self) -> Result<()> {
        info!(
            "Starting matrix multiplication server on {} with HTTP API on {}",
            self.address, self.challenge_address
        );

        let (_, m) = self.matrix_dimensions;
        let vector = generate_challenge_vector(m);

        info!("Server generated challenge vector of size {}", m);

        let app_state = AppState {
            vector: Arc::new(Mutex::new(vector)),
        };

        let http_state = app_state.clone();
        let http_server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(http_state.clone()))
                .route("/", web::get().to(get_challenge))
        })
        .bind(&self.challenge_address)?
        .run();

        let http_handle = tokio::spawn(http_server);
        info!(
            "HTTP challenge server running at {}",
            self.challenge_address
        );

        let config = ServerConfig {
            listen_address: self.address.clone(),
            verification_key_path: PathBuf::from("mpk.bin"),
        };

        let app_state_for_handler = app_state.clone();
        let server = ServerApp::new(config)?
            .with_valid_proof_handler(move |client_id, public_inputs| {
                let string_inputs: Vec<String> = public_inputs
                    .iter()
                    .map(|input| utils::field_to_string(*input))
                    .collect();
                info!(
                    "Client {} provided valid proof. Public inputs from proof: {:?}",
                    client_id, string_inputs
                );

                let (vector_str, result_str) = string_inputs.split_at(m);

                let proved_vector: Vec<u64> =
                    vector_str.iter().filter_map(|s| s.parse().ok()).collect();

                let mut expected_vector = app_state_for_handler.vector.lock().unwrap();

                if proved_vector == *expected_vector {
                    info!("Successfully verified: Client provided a valid proof");

                    let proved_result: Vec<u64> =
                        result_str.iter().filter_map(|s| s.parse().ok()).collect();
                    info!("Result from proof: {:?}", proved_result);

                    let new_vector = generate_challenge_vector(m);
                    *expected_vector = new_vector;
                } else {
                    info!("Verification MISMATCH: Client used incorrect vector in proof");
                }
                Ok(())
            })
            .with_invalid_proof_handler(|client_id, reason| {
                info!("Client {} provided invalid proof: {}", client_id, reason);
                Ok(())
            })
            .with_error_handler(|client_id, error| {
                info!("Error occurred for client {}: {}", client_id, error);
                Ok(())
            });

        server.run().await?;
        http_handle.abort();

        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    vector: Arc<Mutex<Vec<u64>>>,
}

async fn get_challenge(data: web::Data<AppState>) -> impl Responder {
    let vector = data.vector.lock().unwrap().clone();
    HttpResponse::Ok().json(crate::challenge::ChallengeResponse { vector })
}

fn generate_challenge_vector(m: usize) -> Vec<u64> {
    let mut rng = rand::thread_rng();
    let vector = (0..m).map(|_| rng.gen_range(0..100)).collect();
    info!("Generated vector: {:?}", vector);
    vector
}
