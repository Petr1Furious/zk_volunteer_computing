use ark_bls12_381::Fr;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::SynthesisError;
use zkvc::circuit::{ConstraintGenerator, ZkCircuitContext};

#[derive(Clone)]
pub struct AdderCircuit {
    pub x: Fr,
    pub y: Fr,
}

impl ConstraintGenerator<Fr> for AdderCircuit {
    fn generate_constraints(
        &self,
        context: &mut ZkCircuitContext<Fr>,
    ) -> Result<(), SynthesisError> {
        let x_var = context.new_public_input(|| Ok(self.x))?;
        let y_var = context.new_witness(|| Ok(self.y))?;
        let sum_var = &x_var + &y_var;

        let expected_sum = context.new_public_input(|| Ok(self.x + self.y))?;
        sum_var.enforce_equal(&expected_sum)?;
        Ok(())
    }
}
