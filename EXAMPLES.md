# zkvc Examples Guide

This document provides detailed explanations of the example applications included in the zkvc crate.

## Overview

The examples demonstrate different use cases of zero-knowledge proofs in volunteer computing:

1. **Simple Adder**: Basic arithmetic operations
2. **Factorization Example**: Proving knowledge of prime factors
3. **Matrix Multiplication**: Complex computations with hash-based verification

## Simple Adder Example

A basic example showing addition of two numbers with zero-knowledge proofs.

### Purpose
This is a minimal example designed to demonstrate the basic structure of a zero-knowledge proof system. It shows:
- How to define a simple circuit
- How to handle public and private inputs
- Basic constraint generation
- The complete flow from setup to proof generation and verification

The example is intentionally simple to help users understand the core concepts before moving to more complex applications.

### Setup

```bash
cargo run --example simple-adder -- setup
```

### Server

```bash
cargo run --example simple-adder -- server
```

### Client

```bash
cargo run --example simple-adder -- client --x 3 --y 5
```

### Circuit Implementation

```rust
pub struct AdderCircuit {
    pub x: Fr,
    pub y: Fr,
}

impl ConstraintGenerator<Fr> for AdderCircuit {
    fn generate_constraints(
        &self,
        context: &mut ZkCircuitContext<Fr>,
    ) -> Result<(), SynthesisError> {
        let x_var = context.new_witness(|| Ok(self.x))?;
        let y_var = context.new_witness(|| Ok(self.y))?;
        let sum = &x_var + &y_var;
        let expected_sum = context.new_public_input(|| Ok(self.x + self.y))?;
        sum.enforce_equal(&expected_sum)?;
        Ok(())
    }
}
```

## Factorization Example

This example demonstrates how to prove knowledge of prime factors without revealing them.

### Purpose
This example shows how to separate computation from proof generation. The key aspects are:
- The server generates a number to factor
- Clients perform the factorization outside the circuit
- The circuit only proves knowledge of the factors
- The actual computation (factorization) is done efficiently in normal code
- The zero-knowledge proof ensures clients can't fake the factors

This approach is useful when the computation is complex or when you want to use existing efficient algorithms outside the circuit.

### Setup

```bash
cargo run --example factorization -- setup
```

This generates:
- `fpk.bin`: Proving key
- `fvk.bin`: Verification key

### Server

```bash
cargo run --example factorization -- server
```

The server:
1. Generates a product of two primes
2. Exposes an HTTP endpoint for challenge distribution
3. Verifies proofs from clients

### Client

```bash
cargo run --example factorization -- client
```

The client:
1. Requests a challenge from the server
2. Factorizes the number
3. Generates a zero-knowledge proof
4. Sends the proof to the server

### Circuit Implementation

```rust
pub struct FactorizationCircuit {
    pub p1: u64,
    pub p2: u64,
    pub product: u64,
}

impl ConstraintGenerator<Fr> for FactorizationCircuit {
    fn generate_constraints(
        &self,
        context: &mut ZkCircuitContext<Fr>,
    ) -> Result<(), SynthesisError> {
        let p1_var = context.new_witness(|| Ok(Fr::from(self.p1)))?;
        let p2_var = context.new_witness(|| Ok(Fr::from(self.p2)))?;
        let calculated_product = &p1_var * &p2_var;
        let expected_product = context.new_public_input(|| Ok(Fr::from(self.product)))?;
        calculated_product.enforce_equal(&expected_product)?;
        Ok(())
    }
}
```

## Matrix Multiplication Example

A more complex example demonstrating matrix-vector multiplication with optional hash-based verification.

### Purpose
This example demonstrates computation inside the circuit with multiple security features:
- Clients have private matrices they want to keep secret
- The server provides a public vector to multiply with
- The computation (matrix-vector multiplication) is done inside the circuit
- The result vector is public and verifiable
- Optional hash-based verification prevents clients from using a different matrix than claimed
- The zero-knowledge proof prevents clients from:
  - Using a different input vector
  - Providing incorrect results
  - Using a different matrix than claimed (when hash verification is enabled)

This approach is useful when you need to verify the computation itself, not just its result, and when you want to ensure the computation was done exactly as specified.

The matrix could also be a public input, in which case the computation would be offloaded to the clients, and the server would only verify the proof.

### Setup

```bash
cargo run --example matrix-multiplication -- setup
```

### Server

```bash
cargo run --example matrix-multiplication -- server
```

### Client

```bash
cargo run --example matrix-multiplication -- client
```

### Circuit Implementation

```rust
pub struct MatrixMultiplicationCircuit {
    private_matrix: Vec<Vec<u64>>,
    public_vector: Vec<u64>,
    result: Vec<u64>,
    matrix_hash: Fr,
    use_hash: bool,
}

impl ConstraintGenerator<Fr> for MatrixMultiplicationCircuit {
    fn generate_constraints(
        &self,
        context: &mut ZkCircuitContext<Fr>,
    ) -> Result<(), SynthesisError> {
        // Matrix multiplication constraints
        for i in 0..self.private_matrix.len() {
            let mut row_sum = FpVar::<Fr>::zero();
            for j in 0..self.private_matrix[i].len() {
                let matrix_val = context.new_witness(|| Ok(Fr::from(self.private_matrix[i][j])))?;
                let vector_val = context.new_public_input(|| Ok(Fr::from(self.public_vector[j])))?;
                row_sum += &matrix_val * &vector_val;
            }
            let expected_result = context.new_public_input(|| Ok(Fr::from(self.result[i])))?;
            row_sum.enforce_equal(&expected_result)?;
        }

        // Hash verification if enabled
        if self.use_hash {
            // Hash verification constraints
        }

        Ok(())
    }
}
```
