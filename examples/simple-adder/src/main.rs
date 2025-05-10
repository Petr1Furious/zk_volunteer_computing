use ark_bls12_381::Fr;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::SynthesisError;
use clap::{Parser, Subcommand};
use log::{info, LevelFilter};
use zkvc::circuit::{ConstraintGenerator, ZkCircuitContext};
use zkvc::client::{ClientApp, ClientConfig};
use zkvc::server::{ServerApp, ServerConfig};
use zkvc::setup;

#[derive(Clone)]
struct AdderCircuit {
    x: Fr,
    y: Fr,
}

impl ConstraintGenerator<Fr> for AdderCircuit {
    fn generate_constraints(
        &self,
        context: &mut ZkCircuitContext<Fr>,
    ) -> Result<(), SynthesisError> {
        let x_var = context.new_public_input(|| Ok(self.x))?;
        let y_var = context.new_witness(|| Ok(self.y))?;
        let sum_var = &x_var + &y_var;

        let expected_sum = context.new_public_input(|| Ok(self.x + self.y))?;
        sum_var.enforce_equal(&expected_sum)?;
        Ok(())
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate proving and verification keys
    Setup,
    /// Start verification server
    Server {
        /// Server address to listen on
        #[arg(short, long, default_value = "127.0.0.1:65432")]
        address: String,
    },
    /// Generate and send proof
    Client {
        /// Server address to connect to
        #[arg(short, long, default_value = "http://127.0.0.1:65432")]
        server_url: String,
        /// First number to add
        #[arg(short, long, default_value = "3")]
        x: u32,
        /// Second number to add
        #[arg(short, long, default_value = "5")]
        y: u32,
    },
    /// Verify proof locally from file
    Verify,
}

fn setup() -> Result<(), anyhow::Error> {
    info!("Starting setup phase");
    let circuit = AdderCircuit {
        x: Fr::from(0u32),
        y: Fr::from(0u32),
    };

    setup::generate_keys_to_files(Box::new(circuit), "pk.bin", "vk.bin")?;

    info!("Setup complete: pk.bin and vk.bin created.");
    Ok(())
}

async fn run_client(server_url: String, x: u32, y: u32) -> Result<(), anyhow::Error> {
    info!("Starting client");
    let config = ClientConfig {
        server_url,
        proving_key_path: "pk.bin".to_string(),
        proof_path: "proof.json".to_string(),
    };

    let mut client = ClientApp::new(config);
    client.load_proving_key()?;

    let circuit = AdderCircuit {
        x: Fr::from(x),
        y: Fr::from(y),
    };

    let proof_request = client.generate_proof(Box::new(circuit))?;

    client.save_proof(&proof_request)?;
    info!("Proof saved to file");

    let response = client.send_proof(proof_request).await?;
    info!("Server response: {}", response);

    Ok(())
}

async fn run_server(address: String) -> Result<(), anyhow::Error> {
    info!("Starting server on {}", address);
    let config = ServerConfig {
        listen_address: address,
        verification_key_path: "vk.bin".to_string(),
    };

    let mut server = ServerApp::new(config);
    server.load_verification_key()?;

    server.run_server().await?;

    Ok(())
}

fn local_verify() -> Result<(), anyhow::Error> {
    info!("Performing local verification");
    let result = zkvc::server::verify_proof_from_file("proof.json", "vk.bin")?;

    info!(
        "Verification result: {}",
        if result { "Valid" } else { "Invalid" }
    );

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
        Commands::Client { server_url, x, y } => run_client(server_url, x, y).await?,
        Commands::Verify => local_verify()?,
    }

    Ok(())
} 