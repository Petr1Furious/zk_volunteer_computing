use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize)]
pub struct ProofRequest {
    pub client_id: String,
    pub proof: String,
    pub public_inputs: Vec<String>,
}

pub struct WrappedConstraintSystem<F: PrimeField> {
    cs: ConstraintSystemRef<F>,
}

impl<F: PrimeField> Into<Namespace<F>> for WrappedConstraintSystem<F> {
    fn into(self) -> Namespace<F> {
        self.cs.into()
    }
}

#[derive(Clone)]
pub struct ZkCircuitContext<F: PrimeField> {
    cs: ConstraintSystemRef<F>,
    public_inputs: Vec<F>,
}

impl<F: PrimeField> ZkCircuitContext<F> {
    pub fn new(cs: ConstraintSystemRef<F>) -> Self {
        Self {
            cs,
            public_inputs: Vec::new(),
        }
    }

    pub fn new_public_input(
        &mut self,
        f: impl FnOnce() -> Result<F, SynthesisError>,
    ) -> Result<FpVar<F>, SynthesisError> {
        let value = f()?;
        self.public_inputs.push(value);
        FpVar::new_input(self.cs.clone(), || Ok(value))
    }

    pub fn new_witness(
        &self,
        f: impl FnOnce() -> Result<F, SynthesisError>,
    ) -> Result<FpVar<F>, SynthesisError> {
        FpVar::new_witness(self.cs.clone(), f)
    }

    pub fn get_public_inputs(self) -> Vec<F> {
        self.public_inputs
    }

    pub fn get_wrapped_cs(&self) -> WrappedConstraintSystem<F> {
        WrappedConstraintSystem {
            cs: self.cs.clone(),
        }
    }
}

pub trait ConstraintGenerator<F: PrimeField> {
    fn generate_constraints(&self, context: &mut ZkCircuitContext<F>)
        -> Result<(), SynthesisError>;
}

pub struct ZkCircuit<F: PrimeField> {
    pub generator: Box<dyn ConstraintGenerator<F>>,
    pub public_inputs: Arc<Mutex<Vec<F>>>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ZkCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut ctx = ZkCircuitContext::new(cs);
        self.generator.generate_constraints(&mut ctx)?;

        *self.public_inputs.lock().unwrap() = ctx.get_public_inputs();
        Ok(())
    }
}
