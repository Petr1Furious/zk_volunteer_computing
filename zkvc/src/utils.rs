use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

pub(crate) const VERIFY_PATH: &str = "/verify";

pub fn field_to_string<F: PrimeField>(f: F) -> String {
    let big_int = BigUint::from_bytes_le(&f.into_repr().to_bytes_le());
    big_int.to_string()
}

pub fn field_from_string<F: PrimeField>(s: &str) -> Result<F, anyhow::Error> {
    let big_int = BigUint::parse_bytes(s.as_bytes(), 10)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse decimal string"))?;
    let bytes = big_int.to_bytes_le();
    F::from_random_bytes(&bytes).ok_or_else(|| anyhow::anyhow!("Failed to parse field element"))
}
