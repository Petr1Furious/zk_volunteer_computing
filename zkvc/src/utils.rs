use ark_ff::PrimeField;

pub fn field_to_string<F: PrimeField>(f: F) -> String {
    let s = f.into_repr().to_string();
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn field_from_string<F: PrimeField>(s: &str) -> Result<F, anyhow::Error> {
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() {
        Ok(F::zero())
    } else {
        F::from_str(trimmed).map_err(|_| anyhow::anyhow!("Failed to parse field element"))
    }
}
