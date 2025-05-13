use std::path::PathBuf;

use ark_bls12_381::Fr;
use clap::{Parser, Subcommand};
use log::{info, LevelFilter};
use url::Url;
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
        #[arg(short, long, default_value = "127.0.0.1:65432")]
        address: String,
    },
    Client {
        #[arg(short, long, default_value = "http://127.0.0.1:65432")]
        server_url: String,
        #[arg(short, long, default_value = "3")]
        x: u32,
        #[arg(short, long, default_value = "5")]
        y: u32,
        #[arg(short, long, default_value = "client-1")]
        client_id: String,
    },
}

fn setup() -> Result<(), anyhow::Error> {
    info!("Starting setup phase");
    let circuit = circuit::AdderCircuit {
        x: Fr::from(0u32),
        y: Fr::from(0u32),
    };

    setup::generate_keys_to_files(
        Box::new(circuit),
        &PathBuf::from("pk.bin"),
        &PathBuf::from("vk.bin"),
    )?;

    info!("Setup complete: pk.bin and vk.bin created.");
    Ok(())
}

async fn run_client(
    server_url: String,
    x: u32,
    y: u32,
    client_id: String,
) -> Result<(), anyhow::Error> {
    info!("Starting client {}", client_id);
    let config = ClientConfig {
        server_url: Url::parse(&server_url)?,
        proving_key_path: PathBuf::from("pk.bin"),
        proof_path: Some(PathBuf::from("proof.json")),
        client_id,
    };

    let client = ClientApp::new(config)?;

    let circuit = circuit::AdderCircuit {
        x: Fr::from(x),
        y: Fr::from(y),
    };

    let response = client.generate_and_send_proof(Box::new(circuit)).await?;
    match response {
        VerificationResponse::Valid { result } => {
            info!("Proof is valid!");
            if let Some(result) = result {
                info!("Result values: {:?}", result);
            }
        }
        VerificationResponse::Invalid { reason } => {
            info!("Invalid proof: {}", reason);
        }
        VerificationResponse::Error { error } => {
            info!("Error: {}", error);
        }
    }

    Ok(())
}

async fn run_server(address: String) -> Result<(), anyhow::Error> {
    info!("Starting server on {}", address);
    let config = ServerConfig {
        listen_address: address,
        verification_key_path: PathBuf::from("vk.bin"),
    };

    let server = ServerApp::new(config)?
        .with_valid_proof_handler(|client_id, inputs| {
            let string_inputs: Vec<String> = inputs
                .iter()
                .map(|input| utils::field_to_string(*input))
                .collect();
            info!(
                "Client {} provided valid proof with inputs: {:?}",
                client_id, string_inputs
            );
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
    info!("Starting application");

    let cli = Cli::parse();

    match cli.command {
        Commands::Setup => setup()?,
        Commands::Server { address } => run_server(address).await?,
        Commands::Client {
            server_url,
            x,
            y,
            client_id,
        } => run_client(server_url, x, y, client_id).await?,
    }

    Ok(())
}
