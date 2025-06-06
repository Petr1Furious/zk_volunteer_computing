use crate::circuit::{ConstraintGenerator, ZkCircuit};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize as _;
use ark_snark::CircuitSpecificSetupSNARK as _;
use log::debug;
use rand::thread_rng;
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Instant,
};

pub fn generate_keys(
    generator: Box<dyn ConstraintGenerator<Fr>>,
) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>), anyhow::Error> {
    let start = Instant::now();
    let public_inputs: Arc<Mutex<Vec<Fr>>> = Arc::new(Mutex::new(Vec::new()));
    let circuit = ZkCircuit {
        generator,
        public_inputs: Arc::clone(&public_inputs),
    };

    let mut rng = thread_rng();
    let (pk, vk) = Groth16::<Bls12_381>::setup(circuit, &mut rng)?;
    debug!("Key generation completed in {:?}", start.elapsed());
    Ok((pk, vk))
}

pub fn generate_keys_to_files(
    generator: Box<dyn ConstraintGenerator<Fr>>,
    pk_path: &Path,
    vk_path: &Path,
) -> Result<(), anyhow::Error> {
    let start = Instant::now();
    let (pk, vk) = generate_keys(generator)?;

    let mut pk_file = std::fs::File::create(pk_path)?;
    pk.serialize_unchecked(&mut pk_file)?;

    let mut vk_file = std::fs::File::create(vk_path)?;
    vk.serialize_unchecked(&mut vk_file)?;

    debug!(
        "Key generation and saving to files completed in {:?}",
        start.elapsed()
    );
    Ok(())
}
