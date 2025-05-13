use std::path::PathBuf;

use clap::{Parser, Subcommand};
use log::{info, LevelFilter};
use rand::Rng;
use zkvc::setup;

mod challenge;
mod circuit;
mod client;
mod server;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Setup {
        #[arg(long, default_value_t = false)]
        use_hash: bool,
        #[arg(long, default_value_t = 3)]
        matrix_height: usize,
        #[arg(long, default_value_t = 3)]
        matrix_width: usize,
    },
    Server {
        #[arg(short, long, default_value = "127.0.0.1:65433")]
        address: String,
        #[arg(short, long, default_value = "127.0.0.1:65434")]
        challenge_address: String,
        #[arg(long, default_value_t = 3)]
        matrix_height: usize,
        #[arg(long, default_value_t = 3)]
        matrix_width: usize,
    },
    Client {
        #[arg(short, long, default_value = "http://127.0.0.1:65433")]
        server_url: String,
        #[arg(long, default_value = "http://127.0.0.1:65434")]
        challenge_url: String,
        #[arg(short, long, default_value = "client-matrix-1")]
        client_id: String,
        #[arg(long, default_value_t = 3)]
        matrix_height: usize,
        #[arg(long, default_value_t = 3)]
        matrix_width: usize,
        #[arg(long, default_value_t = false)]
        use_hash: bool,
    },
}

fn setup_keys(
    use_hash: bool,
    matrix_height: usize,
    matrix_width: usize,
) -> Result<(), anyhow::Error> {
    info!("Starting setup phase for MatrixMultiplicationCircuit");

    let circuit = circuit::MatrixMultiplicationCircuit::new(
        vec![vec![0; matrix_width]; matrix_height],
        vec![0; matrix_width],
        use_hash,
    );

    setup::generate_keys_to_files(
        Box::new(circuit),
        &PathBuf::from("mpk.bin"),
        &PathBuf::from("mvk.bin"),
    )?;

    info!("Setup complete: mpk.bin and mvk.bin created.");
    Ok(())
}

fn generate_random_matrix(height: usize, width: usize) -> Vec<Vec<u64>> {
    let mut rng = rand::thread_rng();
    (0..height)
        .map(|_| (0..width).map(|_| rng.gen_range(0..10)).collect())
        .collect()
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

    let cli = Cli::parse();

    match cli.command {
        Commands::Setup {
            use_hash,
            matrix_height,
            matrix_width,
        } => setup_keys(use_hash, matrix_height, matrix_width)?,
        Commands::Server {
            address,
            challenge_address,
            matrix_height,
            matrix_width,
        } => {
            let server = server::MatrixMultiplicationServer::new(
                address,
                challenge_address,
                (matrix_height, matrix_width),
            );
            server.run().await?;
        }
        Commands::Client {
            server_url,
            challenge_url,
            client_id,
            matrix_height,
            matrix_width,
            use_hash,
        } => {
            let private_matrix = generate_random_matrix(matrix_height, matrix_width);
            let client = client::MatrixMultiplicationClient::new(
                server_url,
                challenge_url,
                client_id,
                private_matrix,
                use_hash,
            );
            client.run().await?;
        }
    }

    Ok(())
}
