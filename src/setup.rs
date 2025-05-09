use crate::circuit::{ConstraintGenerator, ZkCircuit};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize as _, CanonicalSerialize as _};
use ark_snark::CircuitSpecificSetupSNARK as _;
use rand::thread_rng;
use std::sync::Arc;

pub fn generate_keys(
    generator: Box<dyn ConstraintGenerator<Fr>>,
) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>), anyhow::Error> {
    let public_inputs: Arc<[Fr]> = Arc::new([]);
    let circuit = ZkCircuit {
        generator,
        public_inputs: Arc::clone(&public_inputs),
    };

    let mut rng = thread_rng();
    let (pk, vk) = Groth16::<Bls12_381>::setup(circuit, &mut rng)?;
    Ok((pk, vk))
}

pub fn generate_keys_to_files(
    generator: Box<dyn ConstraintGenerator<Fr>>,
    pk_path: &str,
    vk_path: &str,
) -> Result<(), anyhow::Error> {
    let (pk, vk) = generate_keys(generator)?;

    let mut pk_file = std::fs::File::create(pk_path)?;
    pk.serialize_uncompressed(&mut pk_file)?;

    let mut vk_file = std::fs::File::create(vk_path)?;
    vk.serialize_uncompressed(&mut vk_file)?;
    drop(vk_file);

    let vk_bytes = std::fs::read(vk_path)?;
    println!("bytes: {:?}", vk_bytes);
    let _ = VerifyingKey::<Bls12_381>::deserialize_uncompressed(&*vk_bytes).unwrap();

    Ok(())
}
