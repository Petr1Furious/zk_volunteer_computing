//! # zkvc - Zero Knowledge Volunteer Computing
//! 
//! A Rust library for building zero-knowledge proof-based volunteer computing systems. This library provides a framework
//! for creating distributed computing applications where clients can prove they performed computations correctly without
//! revealing their private inputs.
//! 
//! ## Quick Start
//! 
//! Add the following to your `Cargo.toml`:
//! 
//! ```toml
//! [dependencies]
//! zkvc = "0.1.0"
//! ark-bls12-381 = "0.3"
//! ark-r1cs-std = { version = "0.3", features = ["std"] }
//! ark-relations = "0.3"
//! ```
//! 
//! ## Basic Usage
//! 
//! ### 1. Define Your Circuit
//! 
//! First, define your computation as a circuit by implementing the `ConstraintGenerator` trait:
//! 
//! ```rust
//! use ark_bls12_381::Fr;
//! use ark_relations::r1cs::SynthesisError;
//! use zkvc::circuit::{ConstraintGenerator, ZkCircuitContext};
//! 
//! pub struct MyCircuit {
//!     // Your circuit's private and public inputs
//!     private_input: u64,
//!     public_input: u64,
//! }
//! 
//! impl ConstraintGenerator<Fr> for MyCircuit {
//!     fn generate_constraints(
//!         &self,
//!         context: &mut ZkCircuitContext<Fr>,
//!     ) -> Result<(), SynthesisError> {
//!         // Create private witness
//!         let private_var = context.new_witness(|| Ok(Fr::from(self.private_input)))?;
//!         
//!         // Create public input
//!         let public_var = context.new_public_input(|| Ok(Fr::from(self.public_input)))?;
//!         
//!         // Define your constraints
//!         private_var.enforce_equal(&public_var)?;
//!         
//!         Ok(())
//!     }
//! }
//! ```
//! 
//! ### 2. Setup Phase
//! 
//! Generate proving and verification keys for your circuit:
//! 
//! ```rust
//! use std::path::PathBuf;
//! use zkvc::setup;
//! 
//! let circuit = MyCircuit {
//!     private_input: 0,
//!     public_input: 0,
//! };
//! 
//! setup::generate_keys_to_files(
//!     Box::new(circuit),
//!     &PathBuf::from("pk.bin"),
//!     &PathBuf::from("vk.bin"),
//! )?;
//! ```
//! 
//! ### 3. Server Implementation
//! 
//! Create a server that verifies proofs from clients:
//! 
//! ```rust
//! use zkvc::server::{ServerApp, ServerConfig};
//! 
//! let config = ServerConfig {
//!     listen_address: "127.0.0.1:65432".to_string(),
//!     verification_key_path: PathBuf::from("vk.bin"),
//! };
//! 
//! let server = ServerApp::new(config)?
//!     .with_valid_proof_handler(|client_id, public_inputs| {
//!         println!("Client {} provided valid proof with inputs: {:?}", client_id, public_inputs);
//!         Ok(())
//!     })
//!     .with_invalid_proof_handler(|client_id, reason| {
//!         println!("Client {} provided invalid proof: {}", client_id, reason);
//!         Ok(())
//!     })
//!     .with_error_handler(|client_id, error| {
//!         println!("Client {} encountered an error: {}", client_id, error);
//!         Ok(())
//!     });
//! 
//! server.run().await?;
//! ```
//! 
//! ### 4. Client Implementation
//! 
//! Create a client that generates and sends proofs:
//! 
//! ```rust
//! use zkvc::client::{ClientApp, ClientConfig};
//! use url::Url;
//! 
//! let config = ClientConfig {
//!     server_url: Url::parse("http://127.0.0.1:65432")?,
//!     proving_key_path: PathBuf::from("pk.bin"),
//!     proof_path: Some(PathBuf::from("proof.json")),
//!     client_id: "client-1".to_string(),
//! };
//! 
//! let client = ClientApp::new(config)?;
//! 
//! let circuit = MyCircuit {
//!     private_input: 42,
//!     public_input: 42,
//! };
//! 
//! let response = client.generate_and_send_proof(Box::new(circuit)).await?;
//! ```
//! 
//! ## Arkworks Gadgets
//! 
//! The library supports Arkworks gadgets for complex operations. Here's an example of using MiMC hash:
//! 
//! ```rust
//! use ark_r1cs_std::ToBytesGadget;
//! use arkworks_mimc::{
//!     constraints::{MiMCNonFeistelCRHGadget, MiMCVar},
//!     params::mimc_7_91_bls12_381::{MIMC_7_91_BLS12_381_PARAMS, MIMC_7_91_BLS12_381_ROUND_KEYS},
//! };
//! 
//! // Inside your circuit implementation:
//! let public_zero = context.new_witness(|| Ok(Fr::from(0u64)))?;
//! let public_round_keys = MIMC_7_91_BLS12_381_ROUND_KEYS
//!     .iter()
//!     .map(|x| context.new_witness(|| Ok(*x)))
//!     .collect::<Result<Vec<_>, _>>()?;
//! 
//! let mimc_var = MiMCVar::<Fr, MIMC_7_91_BLS12_381_PARAMS>::new(
//!     1,
//!     public_zero,
//!     public_round_keys
//! );
//! 
//! let value = context.new_witness(|| Ok(Fr::from(42)))?;
//! let hash = MiMCNonFeistelCRHGadget::<Fr, MIMC_7_91_BLS12_381_PARAMS>::evaluate(
//!     &mimc_var,
//!     &FpVar::<Fr>::Constant(Fr::from(0u64)).to_bytes()?,
//!     &value.to_bytes()?,
//! )?;
//! ```

pub mod circuit;
pub mod client;
pub mod response;
pub mod server;
pub mod setup;
pub mod utils;
