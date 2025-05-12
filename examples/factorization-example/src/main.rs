use clap::{Parser, Subcommand};
use log::{info, LevelFilter};
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
        Commands::Setup => {
            setup_keys()?;
        }
        Commands::Server {
            address,
            prime_bits,
            challenge_address,
        } => {
            let server = server::FactorizationServer::new(address, challenge_address, prime_bits);
            server.run().await?;
        }
        Commands::Client {
            server_url,
            challenge_url,
            p1,
            p2,
            product,
            client_id,
        } => {
            let client = client::FactorizationClient::new(server_url, challenge_url, client_id);
            client.run(p1, p2, product).await?;
        }
    }

    Ok(())
}
