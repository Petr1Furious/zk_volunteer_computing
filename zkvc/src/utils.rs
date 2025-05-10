use ark_ff::{BigInteger, PrimeField};

pub fn field_to_string<F: PrimeField>(f: F) -> String {
    let bytes = f.into_repr().to_bytes_le();
    hex::encode(bytes)
}

pub fn field_from_string<F: PrimeField>(s: &str) -> Result<F, anyhow::Error> {
    let bytes = hex::decode(s).map_err(|_| anyhow::anyhow!("Failed to decode hex string"))?;
    F::from_random_bytes(&bytes).ok_or_else(|| anyhow::anyhow!("Failed to parse field element"))
}
