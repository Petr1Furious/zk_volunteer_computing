use ark_groth16::Groth16;
use ark_bls12_381::Bls12_381;
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use rand::thread_rng;
use std::fs::File;
use ark_snark::CircuitSpecificSetupSNARK;
use zkvc::circuit;

fn main() -> anyhow::Result<()> {
    let rng = &mut thread_rng();
    let dummy_circuit = circuit::ExampleCircuit::<ark_bls12_381::Fr> {
        x: ark_bls12_381::Fr::zero(),
        y: ark_bls12_381::Fr::zero(),
    };
    let (pk, vk) = Groth16::<Bls12_381>::setup(dummy_circuit, rng).unwrap();

    let mut pk_file = File::create("pk.bin")?;
    pk.serialize_uncompressed(&mut pk_file)?;
    let mut vk_file = File::create("vk.bin")?;
    vk.serialize_uncompressed(&mut vk_file)?;
    println!("Setup complete: pk.bin and vk.bin created.");
    Ok(())
}
