use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::str::FromStr;
use zk_volunteer_computing::circuit;

async fn verify(request: web::Json<circuit::ProofRequest>) -> impl Responder {
    let vk_bytes = std::fs::read("vk.bin").expect("vk.bin must exist");
    let vk: VerifyingKey<Bls12_381> = VerifyingKey::deserialize_uncompressed(&*vk_bytes).unwrap();

    let proof_bytes = STANDARD.decode(&request.proof).unwrap();
    let proof: Proof<Bls12_381> = Proof::deserialize_uncompressed(&*proof_bytes).unwrap();
    let inputs: Vec<Fr> = request
        .public_inputs
        .iter()
        .map(|s| Fr::from_str(&s).unwrap())
        .collect();

    let valid = Groth16::<Bls12_381>::verify(&vk, &inputs, &proof).unwrap_or(false);
    if valid {
        HttpResponse::Ok().body("Proof is valid")
    } else {
        HttpResponse::BadRequest().body("Invalid proof")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Verifier listening on http://127.0.0.1:51674");
    HttpServer::new(|| App::new().route("/verify", web::post().to(verify)))
        .bind("127.0.0.1:51674")?
        .run()
        .await
}
