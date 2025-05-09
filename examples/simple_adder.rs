use ark_bls12_381::Fr;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::SynthesisError;
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

fn setup() -> Result<(), anyhow::Error> {
    let circuit = AdderCircuit {
        x: Fr::from(0u32),
        y: Fr::from(0u32),
    };

    setup::generate_keys_to_files(Box::new(circuit), "pk.bin", "vk.bin")?;

    println!("Setup complete: pk.bin and vk.bin created.");
    Ok(())
}

async fn run_client() -> Result<(), anyhow::Error> {
    let config = ClientConfig {
        server_url: "http://127.0.0.1:65432".to_string(),
        proving_key_path: "pk.bin".to_string(),
        proof_path: "proof.json".to_string(),
    };

    let mut client = ClientApp::new(config);
    client.load_proving_key()?;

    let circuit = AdderCircuit {
        x: Fr::from(3u32),
        y: Fr::from(5u32),
    };

    let proof_request = client.generate_proof(Box::new(circuit))?;

    client.save_proof(&proof_request)?;
    println!("Proof saved to file");

    let response = client.send_proof(proof_request).await?;
    println!("Server response: {}", response);

    Ok(())
}

async fn run_server() -> Result<(), anyhow::Error> {
    let config = ServerConfig {
        listen_address: "127.0.0.1:65432".to_string(),
        verification_key_path: "vk.bin".to_string(),
    };

    let mut server = ServerApp::new(config);
    server.load_verification_key()?;

    server.run_server().await?;

    Ok(())
}

fn local_verify() -> Result<(), anyhow::Error> {
    let result = zkvc::server::verify_proof_from_file("proof.json", "vk.bin")?;

    println!(
        "Verification result: {}",
        if result { "Valid" } else { "Invalid" }
    );

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("setup") => setup()?,
        Some("client") => run_client().await?,
        Some("server") => run_server().await?,
        Some("verify") => local_verify()?,
        _ => {
            println!("Usage:");
            println!("  adder_app setup   - Generate proving and verification keys");
            println!("  adder_app server  - Start verification server");
            println!("  adder_app client  - Generate and send proof");
            println!("  adder_app verify  - Verify proof locally from file");
        }
    }

    Ok(())
}
