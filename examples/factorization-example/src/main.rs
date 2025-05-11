use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use clap::{Parser, Subcommand};
use log::{info, LevelFilter};
use num_primes::Generator;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use zkvc::client::{ClientApp, ClientConfig};
use zkvc::response::VerificationResponse;
use zkvc::server::{ServerApp, ServerConfig};
use zkvc::{setup, utils};

mod circuit;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Setup,
    Server {
        #[arg(short, long, default_value = "127.0.0.1:65433")]
        address: String,
        #[arg(long, default_value_t = 32)]
        prime_bits: usize,
        #[arg(short, long, default_value = "127.0.0.1:65434")]
        challenge_address: String,
    },
    Client {
        #[arg(short, long, default_value = "http://127.0.0.1:65433")]
        server_url: String,
        #[arg(long, default_value = "http://127.0.0.1:65434")]
        challenge_url: String,
        #[arg(long)]
        p1: Option<u64>,
        #[arg(long)]
        p2: Option<u64>,
        #[arg(long)]
        product: Option<u64>,
        #[arg(short, long, default_value = "client-factorizer-1")]
        client_id: String,
    },
}

#[derive(Serialize, Deserialize)]
struct ChallengeResponse {
    product: u64,
}

fn setup_keys() -> Result<(), anyhow::Error> {
    info!("Starting setup phase for FactorizationCircuit");
    let circuit = circuit::FactorizationCircuit {
        p1: 0,
        p2: 0,
        product: 0,
    };

    setup::generate_keys_to_files(Box::new(circuit), "fpk.bin", "fvk.bin")?;

    info!("Setup complete: fpk.bin and fvk.bin created.");
    Ok(())
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

#[derive(Clone)]
struct AppState {
    product: Arc<Mutex<u64>>,
    prime_bits: usize,
}

async fn get_challenge(data: web::Data<AppState>) -> impl Responder {
    let product = *data.product.lock().unwrap();
    HttpResponse::Ok().json(ChallengeResponse { product })
}

async fn run_client(
    server_url: String,
    challenge_url: String,
    p1: Option<u64>,
    p2: Option<u64>,
    product: Option<u64>,
    client_id: String,
) -> Result<(), anyhow::Error> {
    info!("Starting factorization client {}", client_id);

    let (p1, p2, product) = if let (Some(p1), Some(p2), Some(product)) = (p1, p2, product) {
        info!(
            "Using provided values: p1={}, p2={}, product={}",
            p1, p2, product
        );
        (p1, p2, product)
    } else {
        info!("Requesting challenge from {}", challenge_url);
        let client = reqwest::Client::new();
        let response = client.get(&challenge_url).send().await?;
        let challenge: ChallengeResponse = response.json().await?;
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
        server_url,
        proving_key_path: "fpk.bin".to_string(),
        proof_path: Some("factor_proof.json".to_string()),
        client_id: client_id.clone(),
    };

    let client = ClientApp::new(config)?;

    let circuit = circuit::FactorizationCircuit { p1, p2, product };

    info!(
        "Client {} generating proof for p1={}, p2={}, product={}",
        client_id, p1, p2, product
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

async fn run_server(
    address: String,
    prime_bits: usize,
    challenge_address: String,
) -> Result<(), anyhow::Error> {
    info!(
        "Starting factorization server on {} with HTTP API on {}",
        address, challenge_address
    );

    let (p1, p2) = generate_two_primes(prime_bits);
    let product_x = p1 * p2;
    info!(
        "Server generated p1={}, p2={}. The number to factor is x = {}",
        p1, p2, product_x
    );

    let app_state = AppState {
        product: Arc::new(Mutex::new(product_x)),
        prime_bits,
    };

    let http_state = app_state.clone();
    let http_server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(http_state.clone()))
            .route("/", web::get().to(get_challenge))
    })
    .bind(&challenge_address)?
    .run();

    let http_handle = tokio::spawn(http_server);
    info!("HTTP challenge server running at {}", challenge_address);

    let config = ServerConfig {
        listen_address: address,
        verification_key_path: "fvk.bin".to_string(),
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

    info!("ZK verification server is ready. Waiting for clients to connect and prove knowledge of factors for {}.", product_x);
    info!("Clients can request the challenge at {}", challenge_address);

    server.run_server().await?;

    http_handle.abort();

    Ok(())
}

fn init_logging() {
    let log_level = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| "info".to_string())
        .parse::<LevelFilter>()
        .unwrap_or(LevelFilter::Info);

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_millis()
        .init();

    info!("Logging initialized with level: {}", log_level);
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    init_logging();
    info!("Starting Factorization ZK example application");

    let cli = Cli::parse();

    match cli.command {
        Commands::Setup => setup_keys()?,
        Commands::Server {
            address,
            prime_bits,
            challenge_address,
        } => {
            if prime_bits > 32 {
                info!("Warning: prime_bits > 32 may lead to product overflow for u64. Max recommended is 32.");
            }
            run_server(address, prime_bits, challenge_address).await?
        }
        Commands::Client {
            server_url,
            challenge_url,
            p1,
            p2,
            product,
            client_id,
        } => run_client(server_url, challenge_url, p1, p2, product, client_id).await?,
    }

    Ok(())
}
