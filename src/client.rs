use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{ProvingKey, create_random_proof};
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::thread_rng;
use reqwest::Client;
use zkvc::circuit;

fn fr_to_string<F: PrimeField>(f: F) -> String {
    let s = f.into_repr().to_string();
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.into()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pk_bytes = std::fs::read("pk.bin")?;
    let pk: ProvingKey<Bls12_381> = ProvingKey::deserialize_uncompressed(&*pk_bytes)?;

    let x = Fr::from(3u32);
    let y = Fr::from(5u32);
    let circuit = circuit::ExampleCircuit { x, y };

    let mut rng = thread_rng();
    let proof = create_random_proof::<Bls12_381, _, _>(circuit, &pk, &mut rng)?;

    let mut proof_bytes = vec![];
    proof.serialize_uncompressed(&mut proof_bytes)?;
    let public_inputs = vec![fr_to_string(x), fr_to_string(y), fr_to_string(x + y)];

    let request = circuit::ProofRequest {
        proof: STANDARD.encode(&proof_bytes),
        public_inputs,
    };
    let client = Client::new();
    let resp = client
        .post("http://127.0.0.1:51674/verify")
        .json(&request)
        .send()
        .await?;
    println!("Server response: {}", resp.text().await?);
    Ok(())
}
