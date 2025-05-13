# Arkworks Integration Guide

This document provides detailed information about how zkvc integrates with the Arkworks ecosystem for zero-knowledge proofs.

## Overview

zkvc uses several key components from the Arkworks ecosystem:

- `ark-bls12-381`: The BLS12-381 elliptic curve implementation
- `ark-groth16`: The Groth16 zero-knowledge proof system
- `ark-r1cs-std`: Standard gadgets for R1CS (Rank-1 Constraint System)
- `ark-relations`: Core traits for constraint systems
- `ark-ff`: Field arithmetic primitives

## Circuit Definition

### Basic Circuit Structure

To define a circuit in zkvc, implement the `ConstraintGenerator` trait:

```rust
use ark_bls12_381::Fr;
use ark_relations::r1cs::SynthesisError;
use zkvc::circuit::{ConstraintGenerator, ZkCircuitContext};

pub struct MyCircuit {
    // Your circuit's private and public inputs
}

impl ConstraintGenerator<Fr> for MyCircuit {
    fn generate_constraints(
        &self,
        context: &mut ZkCircuitContext<Fr>,
    ) -> Result<(), SynthesisError> {
        // Define your circuit's constraints here
        Ok(())
    }
}
```

### Working with Variables

The `ZkCircuitContext` provides methods for creating variables:

```rust
// Create a public input
let public_var = context.new_public_input(|| Ok(Fr::from(42)))?;

// Create a private witness
let witness_var = context.new_witness(|| Ok(Fr::from(secret_value)))?;
```

### Field Operations

zkvc uses the BLS12-381 scalar field for all computations. Basic operations are supported:

```rust
// Addition
let sum = &var1 + &var2;

// Multiplication
let product = &var1 * &var2;

// Equality constraints and any other gadgets
var1.enforce_equal(&var2)?;
```

## Proof System

### Setup Phase

The setup phase generates proving and verification keys:

```rust
use zkvc::setup;

let circuit = MyCircuit { /* ... */ };
setup::generate_keys_to_files(
    Box::new(circuit),
    &PathBuf::from("pk.bin"),
    &PathBuf::from("vk.bin"),
)?;
```

### Proof Generation

Clients generate proofs using their private inputs:

```rust
use zkvc::client::ClientApp;

let client = ClientApp::new(config)?;
let circuit = MyCircuit { /* ... */ };
let response = client.generate_and_send_proof(Box::new(circuit)).await?;
```

### Proof Verification

Servers verify proofs using the verification key:

```rust
use zkvc::server::ServerApp;

// The server automatically verifies proofs using Groth16
let server = ServerApp::new(config)?
    .with_valid_proof_handler(|client_id, public_inputs| {
        // Handle valid proof
    })
    .with_invalid_proof_handler(|client_id, public_inputs| {
        // Handle invalid proof
    })
    .with_error_handler(|client_id, error| {
        // Handle error
    });
```

## Arkworks Gadgets

zkvc supports Arkworks gadgets for complex operations. Here's an example of using MiMC hash gadget to compute a hash of a matrix:

```rust
use ark_bls12_381::Fr;
use ark_r1cs_std::ToBytesGadget;
use arkworks_mimc::{
    constraints::{MiMCNonFeistelCRHGadget, MiMCVar},
    params::mimc_7_91_bls12_381::{MIMC_7_91_BLS12_381_PARAMS, MIMC_7_91_BLS12_381_ROUND_KEYS},
};

// Inside your circuit implementation:
fn generate_constraints(
    &self,
    context: &mut ZkCircuitContext<Fr>,
) -> Result<(), SynthesisError> {
    // Setup MiMC hash gadget
    let public_zero = context.new_witness(|| Ok(Fr::from(0u64)))?;
    let public_round_keys = MIMC_7_91_BLS12_381_ROUND_KEYS
        .iter()
        .map(|x| context.new_witness(|| Ok(*x)))
        .collect::<Result<Vec<_>, _>>()?;

    let mimc_var = MiMCVar::<Fr, MIMC_7_91_BLS12_381_PARAMS>::new(
        1,
        public_zero,
        public_round_keys
    );

    // Compute hash of a value
    let value = context.new_witness(|| Ok(Fr::from(42)))?;
    let hash = MiMCNonFeistelCRHGadget::<Fr, MIMC_7_91_BLS12_381_PARAMS>::evaluate(
        &mimc_var,
        &FpVar::<Fr>::Constant(Fr::from(0u64)).to_bytes()?,
        &value.to_bytes()?,
    )?;

    Ok(())
}
```
