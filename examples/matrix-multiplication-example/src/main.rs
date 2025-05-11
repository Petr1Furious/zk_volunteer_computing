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
    Setup,
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
    },
}

fn setup_keys() -> Result<(), anyhow::Error> {
    info!("Starting setup phase for MatrixMultiplicationCircuit");

    let circuit = circuit::MatrixMultiplicationCircuit::new(vec![vec![0; 3]; 3], vec![0; 3]);

    setup::generate_keys_to_files(Box::new(circuit), "mpk.bin", "mvk.bin")?;

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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .filter_level(LevelFilter::Info)
        .init();
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    init_logging();

    let cli = Cli::parse();

    match cli.command {
        Commands::Setup => {
            setup_keys()?;
        }
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
        } => {
            let private_matrix = generate_random_matrix(matrix_height, matrix_width);
            info!("Generated private matrix: {:?}", private_matrix);

            let client = client::MatrixMultiplicationClient::new(
                server_url,
                challenge_url,
                client_id,
                private_matrix,
            );
            client.run().await?;
        }
    }

    Ok(())
}
