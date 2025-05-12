use ark_bls12_381::Fr;
use ark_crypto_primitives::crh::constraints::CRHGadget as _;
use ark_crypto_primitives::crh::poseidon::constraints::{CRHGadget, PoseidonRoundParamsVar};
use ark_crypto_primitives::crh::poseidon::sbox::PoseidonSbox;
use ark_crypto_primitives::crh::poseidon::{Poseidon, PoseidonRoundParams};
use ark_r1cs_std::alloc::AllocVar as _;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::ToBytesGadget as _;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use zkvc::circuit::{ConstraintGenerator, ZkCircuitContext};

#[derive(Clone, Default)]
pub struct MatrixHashParams;

impl PoseidonRoundParams<Fr> for MatrixHashParams {
    const WIDTH: usize = 6;
    const FULL_ROUNDS_BEGINNING: usize = 8;
    const FULL_ROUNDS_END: usize = 8;
    const PARTIAL_ROUNDS: usize = 56;
    const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
}

#[derive(Clone, Debug)]
pub struct MatrixMultiplicationCircuit {
    private_matrix: Vec<Vec<u64>>,
    public_vector: Vec<u64>,
    result: Vec<u64>,
    matrix_hash: Fr,
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

        let mut result = vec![0; n];
        for i in 0..n {
            for j in 0..m {
                result[i] += private_matrix[i][j] * public_vector[j];
            }
        }

        let hasher = Poseidon::<Fr, MatrixHashParams>::default();
        let mut matrix_hash = Fr::from(0u64);

        for row in &private_matrix {
            for chunk in row.chunks(4) {
                let mut inputs = [Fr::from(0u64); 4];
                for (i, &val) in chunk.iter().enumerate() {
                    inputs[i] = Fr::from(val);
                }
                let row_hash = hasher.hash_4(inputs);
                matrix_hash = hasher.hash_2(matrix_hash, row_hash);
            }
        }

        Self {
            private_matrix,
            public_vector,
            result,
            matrix_hash,
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

        let matrix_hash_var = context.new_public_input(|| Ok(self.matrix_hash))?;

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

        let hasher = Poseidon::<Fr, MatrixHashParams>::default();
        let params_var = PoseidonRoundParamsVar::<Fr, MatrixHashParams>::new_variable(
            context.get_wrapped_cs(),
            || Ok(hasher),
            ark_r1cs_std::alloc::AllocationMode::Constant,
        )?;

        let mut computed_hash = FpVar::<Fr>::Constant(Fr::from(0u64));
        for row in &matrix_vars {
            for chunk in row.chunks(4) {
                let mut bytes = Vec::new();
                for val in chunk {
                    let val_bytes = val.to_bytes()?;
                    bytes.extend_from_slice(&val_bytes);
                }
                let row_hash = CRHGadget::<Fr, MatrixHashParams>::evaluate(&params_var, &bytes)?;

                let mut bytes = Vec::new();
                let computed_bytes = computed_hash.to_bytes()?;
                let row_bytes = row_hash.to_bytes()?;
                bytes.extend_from_slice(&computed_bytes);
                bytes.extend_from_slice(&row_bytes);
                computed_hash = CRHGadget::<Fr, MatrixHashParams>::evaluate(&params_var, &bytes)?;
            }
        }

        computed_hash.enforce_equal(&matrix_hash_var)?;

        Ok(())
    }
}

impl ConstraintSynthesizer<Fr> for MatrixMultiplicationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut zk_context = ZkCircuitContext::new(cs);
        ConstraintGenerator::generate_constraints(&self, &mut zk_context)
    }
}
