use ark_bls12_381::Fr;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use zkvc::circuit::{ConstraintGenerator, ZkCircuitContext};

#[derive(Clone, Debug)]
pub struct MatrixMultiplicationCircuit {
    private_matrix: Vec<Vec<u64>>,
    public_vector: Vec<u64>,
    result: Vec<u64>,
}

impl MatrixMultiplicationCircuit {
    pub fn new(private_matrix: Vec<Vec<u64>>, public_vector: Vec<u64>) -> Self {
        let n = private_matrix.len();
        let m = private_matrix[0].len();
        assert_eq!(
            public_vector.len(),
            m,
            "Vector size must match matrix width"
        );

        // Compute matrix multiplication
        let mut result = vec![0; n];
        for i in 0..n {
            for j in 0..m {
                result[i] += private_matrix[i][j] * public_vector[j];
            }
        }

        Self {
            private_matrix,
            public_vector,
            result,
        }
    }
}

impl ConstraintGenerator<Fr> for MatrixMultiplicationCircuit {
    fn generate_constraints(
        &self,
        context: &mut ZkCircuitContext<Fr>,
    ) -> Result<(), SynthesisError> {
        let n = self.private_matrix.len();
        let m = self.private_matrix[0].len();

        let matrix_vars: Vec<Vec<_>> = self
            .private_matrix
            .iter()
            .map(|row| {
                row.iter()
                    .map(|&x| context.new_witness(|| Ok(Fr::from(x))))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let vector_vars: Vec<_> = self
            .public_vector
            .iter()
            .map(|&x| context.new_public_input(|| Ok(Fr::from(x))))
            .collect::<Result<Vec<_>, _>>()?;

        let result_vars: Vec<_> = self
            .result
            .iter()
            .map(|&x| context.new_public_input(|| Ok(Fr::from(x))))
            .collect::<Result<Vec<_>, _>>()?;

        for i in 0..n {
            let mut sum = context.new_witness(|| Ok(Fr::from(0u64)))?;
            for j in 0..m {
                let product = &matrix_vars[i][j] * &vector_vars[j];
                sum = &sum + &product;
            }
            sum.enforce_equal(&result_vars[i])?;
        }

        Ok(())
    }
}

impl ConstraintSynthesizer<Fr> for MatrixMultiplicationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut zk_context = ZkCircuitContext::new(cs);
        ConstraintGenerator::generate_constraints(&self, &mut zk_context)
    }
}
