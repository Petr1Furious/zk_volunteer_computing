use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct ExampleCircuit<F: PrimeField> {
    pub x: F,
    pub y: F,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ExampleCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_var = FpVar::new_input(cs.clone(), || Ok(self.x))?;
        let y_var = FpVar::new_input(cs.clone(), || Ok(self.y))?;
        let sum_var = &x_var + &y_var;

        let expected_sum = FpVar::new_input(cs.clone(), || Ok(self.x + self.y))?;
        sum_var.enforce_equal(&expected_sum)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProofRequest {
    pub proof: String,
    pub public_inputs: Vec<String>,
}
