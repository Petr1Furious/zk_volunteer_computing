use ark_bls12_381::Fr;
use ark_crypto_primitives::crh::constraints::TwoToOneCRHGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::ToBytesGadget as _;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use arkworks_mimc::{
    constraints::{MiMCNonFeistelCRHGadget, MiMCVar},
    params::{
        mimc_7_91_bls12_381::{MIMC_7_91_BLS12_381_PARAMS, MIMC_7_91_BLS12_381_ROUND_KEYS},
        round_keys_contants_to_vec,
    },
    MiMC,
};
use zkvc::circuit::{ConstraintGenerator, ZkCircuitContext};

#[derive(Clone, Debug)]
pub struct MatrixMultiplicationCircuit {
    private_matrix: Vec<Vec<u64>>,
    public_vector: Vec<u64>,
    result: Vec<u64>,
    matrix_hash: Fr,
    use_hash: bool,
}

impl MatrixMultiplicationCircuit {
    pub fn new(private_matrix: Vec<Vec<u64>>, public_vector: Vec<u64>, use_hash: bool) -> Self {
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

        let matrix_hash = if use_hash {
            let mimc = MiMC::<Fr, MIMC_7_91_BLS12_381_PARAMS>::new(
                1,
                Fr::from(0u64),
                round_keys_contants_to_vec(&MIMC_7_91_BLS12_381_ROUND_KEYS),
            );

            let mut hash = Fr::from(0u64);
            for row in &private_matrix {
                for val in row {
                    hash = mimc.permute_non_feistel(vec![hash, Fr::from(*val)])[0];
                }
            }
            hash
        } else {
            Fr::from(0u64)
        };

        Self {
            private_matrix,
            public_vector,
            result,
            matrix_hash,
            use_hash,
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

        if self.use_hash {
            let public_zero = context.new_witness(|| Ok(Fr::from(0u64)))?;
            let public_round_keys = round_keys_contants_to_vec(&MIMC_7_91_BLS12_381_ROUND_KEYS)
                .iter()
                .map(|x| context.new_witness(|| Ok(*x)))
                .collect::<Result<Vec<_>, _>>()?;

            let mimc_var =
                MiMCVar::<Fr, MIMC_7_91_BLS12_381_PARAMS>::new(1, public_zero, public_round_keys);

            let mut computed_hash = FpVar::<Fr>::Constant(Fr::from(0u64));

            for row in &matrix_vars {
                for var in row {
                    computed_hash =
                        MiMCNonFeistelCRHGadget::<Fr, MIMC_7_91_BLS12_381_PARAMS>::evaluate(
                            &mimc_var,
                            &computed_hash.to_bytes()?,
                            &var.to_bytes()?,
                        )?;
                }
            }

            let matrix_hash_var = context.new_public_input(|| Ok(self.matrix_hash))?;
            computed_hash.enforce_equal(&matrix_hash_var)?;
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
