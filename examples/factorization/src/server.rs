use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use anyhow::Result;
use log::info;
use num_primes::Generator;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use zkvc::server::{ServerApp, ServerConfig};
use zkvc::utils;

pub struct FactorizationServer {
    address: String,
    challenge_address: String,
    prime_bits: usize,
}

impl FactorizationServer {
    pub fn new(address: String, challenge_address: String, prime_bits: usize) -> Self {
        Self {
            address,
            challenge_address,
            prime_bits,
        }
    }

    pub async fn run(&self) -> Result<()> {
        info!(
            "Starting factorization server on {} with HTTP API on {}",
            self.address, self.challenge_address
        );

        let (p1, p2) = generate_two_primes(self.prime_bits);
        let product_x = p1 * p2;
        info!(
            "Server generated p1={}, p2={}. The number to factor is x = {}",
            p1, p2, product_x
        );

        let app_state = AppState {
            product: Arc::new(Mutex::new(product_x)),
            prime_bits: self.prime_bits,
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
            verification_key_path: PathBuf::from("fvk.bin"),
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

                if let Some(proved_product_str) = string_inputs.get(0) {
                    if let Ok(proved_product_val) = proved_product_str.parse::<u64>() {
                        let expected_product = *app_state_for_handler.product.lock().unwrap();
                        if proved_product_val == expected_product {
                            info!("Successfully verified: Proved product matches server's product {}.", proved_product_val);
                            let (p1, p2) = generate_two_primes(app_state_for_handler.prime_bits);
                            let new_product = p1 * p2;
                            *app_state_for_handler.product.lock().unwrap() = new_product;
                        } else {
                            info!("Verification MISMATCH: Proved product {} DOES NOT match server's product {}.", proved_product_val, expected_product);
                        }
                    } else {
                        info!("Could not parse proved product from string: {}", proved_product_str);
                    }
                } else {
                    info!("No public inputs found in the valid proof to verify product.");
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
    product: Arc<Mutex<u64>>,
    prime_bits: usize,
}

async fn get_challenge(data: web::Data<AppState>) -> impl Responder {
    let product = *data.product.lock().unwrap();
    HttpResponse::Ok().json(crate::challenge::ChallengeResponse { product })
}

fn generate_two_primes(bits: usize) -> (u64, u64) {
    info!("Generating two {}-bit primes...", bits);
    let p1 = Generator::new_prime(bits)
        .to_string()
        .parse::<u64>()
        .expect("Prime 1 is not u64");
    let p2 = Generator::new_prime(bits)
        .to_string()
        .parse::<u64>()
        .expect("Prime 2 is not u64");
    info!("Generated primes: p1 = {}, p2 = {}", p1, p2);
    (p1, p2)
}
