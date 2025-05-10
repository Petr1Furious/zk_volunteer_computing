use ark_bls12_381::Fr;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use zkvc::circuit::{ConstraintGenerator, ZkCircuitContext};

#[derive(Clone, Debug)]
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

impl ConstraintSynthesizer<Fr> for FactorizationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut zk_context = ZkCircuitContext::new(cs);
        ConstraintGenerator::generate_constraints(&self, &mut zk_context)
    }
}
