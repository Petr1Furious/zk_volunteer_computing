# zkvc - Zero Knowledge Volunteer Computing

A Rust library for building zero-knowledge proof-based volunteer computing systems. This library provides a framework for creating distributed computing applications where clients can prove they performed computations correctly without revealing their private inputs or the server redoing the computation.

## Features

- Zero-knowledge proof generation and verification using Groth16 protocol
- Built on top of the Arkworks ecosystem for efficient cryptographic operations
- Client-server architecture for distributed computation
- Support for custom circuit definitions
- Automatic proof generation and verification
- HTTP-based communication between clients and servers
- Configurable proof handlers for custom verification logic

## Quick Start

Add the following to your `Cargo.toml`:

```toml
[dependencies]
zkvc = "0.1.0"
ark-bls12-381 = "0.3"
ark-r1cs-std = { version = "0.3", features = ["std"] }
ark-relations = "0.3"
```

## Examples

The repository includes several example applications, described in [EXAMPLES.md](EXAMPLES.md):

1. **Simple Adder**: A basic example demonstrating addition of two numbers with zero-knowledge proofs.
2. **Factorization Example**: A system where clients prove they know the prime factors of a number without revealing the factors.
3. **Matrix Multiplication**: A more complex example showing matrix-vector multiplication with optional hash-based verification.

To run an example:

```bash
# Setup phase (generates proving and verification keys)
cargo run --example factorization -- setup

# Start the server
cargo run --example factorization -- server

# Run a client
cargo run --example factorization -- client
```

## Architecture

The library consists of several main components:

1. **Circuit Definition**: Define your computation as a circuit using the `ConstraintGenerator` trait.
2. **Setup Phase**: Generate proving and verification keys for your circuit.
3. **Server**: Run a server that verifies proofs from clients.
4. **Client**: Generate proofs and send them to the server for verification.

## Integration with Arkworks

The library is built on top of the Arkworks ecosystem, providing:

- Efficient field arithmetic using BLS12-381 curve
- R1CS (Rank-1 Constraint System) for circuit definition
- Groth16 protocol for zero-knowledge proofs
- Support for custom field elements and gadgets

The details are described in [ARKWORKS.md](ARKWORKS.md).
