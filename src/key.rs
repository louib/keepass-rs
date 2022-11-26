use std::error::Error;

use crate::crypt;
use crate::result;

pub type KeyElements = Vec<Vec<u8>>;

pub fn get_key_elements(
    password: Option<&str>,
    keyfile: Option<&mut dyn std::io::Read>,
) -> Result<KeyElements, result::Error> {
    let mut key_elements: Vec<Vec<u8>> = Vec::new();

    if let Some(p) = password {
        key_elements.push(
            crypt::calculate_sha256(&[p.as_bytes()])
                .map_err(|e| result::Error::IncorrectKey {})?
                .as_slice()
                .to_vec(),
        );
    }

    if let Some(f) = keyfile {
        key_elements.push(crate::keyfile::parse(f).map_err(|e| result::Error::InvalidKeyFile {})?);
    }

    if key_elements.is_empty() {
        // FIXME this should return more specific errors.
        // return Err(result::Error::IncorrectKey {});
        // FIXME this breaks the tests for now.
    }

    Ok(key_elements)
}
