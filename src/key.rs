use std::io::Read;
use std::process::Command;
use std::u8;

use base64::{engine::general_purpose as base64_engine, Engine as _};
use xml::name::OwnedName;
use xml::reader::{EventReader, XmlEvent};

use crate::{crypt::calculate_sha256, error::DatabaseKeyError};

pub type KeyElement = Vec<u8>;
pub type KeyElements = Vec<KeyElement>;

fn parse_xml_keyfile(xml: &[u8]) -> Result<Vec<u8>, DatabaseKeyError> {
    let parser = EventReader::new(xml);

    let mut tag_stack = Vec::new();

    for ev in parser {
        match ev? {
            XmlEvent::StartElement {
                name: OwnedName { ref local_name, .. },
                ..
            } => {
                tag_stack.push(local_name.clone());
            }
            XmlEvent::EndElement { .. } => {
                tag_stack.pop();
            }
            XmlEvent::Characters(s) => {
                // Check if we are at KeyFile/Key/Data
                if tag_stack == ["KeyFile", "Key", "Data"] {
                    let key_base64 = s.as_bytes().to_vec();

                    // Check if the key is base64-encoded. If yes, return decoded bytes
                    return if let Ok(key) = base64_engine::STANDARD.decode(&key_base64) {
                        Ok(key)
                    } else {
                        Ok(key_base64)
                    };
                }
            }
            _ => {}
        }
    }

    Err(DatabaseKeyError::InvalidKeyFile)
}

fn parse_keyfile(buffer: &[u8]) -> Result<KeyElement, DatabaseKeyError> {
    // try to parse the buffer as XML, if successful, use that data instead of full file
    if let Ok(v) = parse_xml_keyfile(&buffer) {
        Ok(v)
    } else if buffer.len() == 32 {
        // legacy binary key format
        Ok(buffer.to_vec())
    } else {
        Ok(calculate_sha256(&[&buffer])?.as_slice().to_vec())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ChallengeResponseKey {
    id: String,
    slot: usize,
}

impl ChallengeResponseKey {
    pub fn get_challenge_response(seed: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(vec![])
    }
}

/// A KeePass key, which might consist of a password and/or a keyfile
#[derive(Debug, Clone, Default)]
pub struct DatabaseKey {
    password: Option<String>,
    keyfile: Option<Vec<u8>>,
    challenge_response_key: Option<ChallengeResponseKey>,
    challenge_response_result: Option<Vec<u8>>,
}

impl DatabaseKey {
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = Some(password.to_string());
        self
    }

    pub fn with_keyfile(mut self, keyfile: &mut dyn Read) -> Result<Self, std::io::Error> {
        let mut buf = Vec::new();
        keyfile.read_to_end(&mut buf)?;

        self.keyfile = Some(buf);

        Ok(self)
    }

    pub fn with_challenge_response_key(mut self, key_slot: usize) -> Self {
        self.challenge_response_key = Some(ChallengeResponseKey {
            id: "".to_string(),
            slot: key_slot,
        });
        self
    }

    pub fn perform_challenge(mut self, kdf_seed: &[u8]) -> Result<Self, DatabaseKeyError> {
        let challenge_response_key = match self.challenge_response_key {
            Some(ref k) => k,
            None => return Ok(self),
        };
        let response = get_challenge_response_from_ykchal(kdf_seed, challenge_response_key.slot)?;

        let response_from_local_secret = get_challenge_response_from_local_secret(
            kdf_seed,
            "d08490df5597c609075a95466a1d4b6dc2dfdc77",
        )?;

        self.challenge_response_result = Some(response_from_local_secret);
        Ok(self)
    }

    pub fn new() -> Self {
        Default::default()
    }

    pub(crate) fn get_key_elements(&self) -> Result<KeyElements, DatabaseKeyError> {
        let mut out = Vec::new();

        if let Some(p) = &self.password {
            out.push(calculate_sha256(&[p.as_bytes()])?.to_vec());
        }

        if let Some(ref f) = self.keyfile {
            out.push(parse_keyfile(f)?);
        }

        if out.is_empty() {
            return Err(DatabaseKeyError::IncorrectKey);
        }

        if let Some(result) = &self.challenge_response_result {
            println!("Adding the challenge response result");
            out.push(calculate_sha256(&[result])?.as_slice().to_vec());
        } else if self.challenge_response_key.is_some() {
            // FIXME I should have a dedicated error for that.
            return Err(DatabaseKeyError::IncorrectKey);
        }

        Ok(out)
    }
}

pub fn get_challenge_response_from_local_secret(
    challenge: &[u8],
    secret: &str,
) -> Result<Vec<u8>, DatabaseKeyError> {
    let mut secret_bytes = hex_to_bytes(&secret)?;

    let mut challenge_bytes = challenge.clone().to_owned();
    let padding = 64 - challenge.len();
    while challenge_bytes.len() < 64 {
        challenge_bytes.push(padding as u8);
    }
    println!("Challenge: {}", bytes_to_hex(&challenge_bytes));

    let response = crate::crypt::calculate_hmac_sha1(&[&challenge_bytes], &secret_bytes)?.to_vec();
    let mut hex_response = bytes_to_hex(&response);
    println!("Response:  {}", &hex_response);
    Ok(response)
}

pub fn get_challenge_response_from_ykchal(
    challenge: &[u8],
    slot: usize,
) -> Result<Vec<u8>, DatabaseKeyError> {
    // TODO verify that the binary is available on the system.
    //
    //
    let mut hex_challenge = bytes_to_hex(&challenge);
    println!("Challenge: {}", &hex_challenge);

    let mut command = Command::new("ykchalresp");
    command.arg(format!("-{}", slot));
    command.arg(hex_challenge);

    let output = command.output()?;

    if !output.status.success() {
        // let stderr = String::from_utf8(output.stderr).unwrap();
        return Err(DatabaseKeyError::ChallengeResponseKeyError);
    }

    let hex_response = match String::from_utf8(output.stdout) {
        Ok(o) => o,
        Err(_e) => return Err(DatabaseKeyError::ChallengeResponseKeyError),
    };

    let mut response = hex_to_bytes(&hex_response)?;
    println!("Response: {}", &hex_response);
    Ok(response)
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, DatabaseKeyError> {
    let mut response: Vec<u8> = vec![];
    let mut hex_string_buffer: String = "".to_string();
    for hex_character in hex.chars() {
        hex_string_buffer.push(hex_character);
        if hex_string_buffer.len() < 2 {
            continue;
        }

        let byte = match u8::from_str_radix(&hex_string_buffer, 16) {
            Ok(b) => b,
            Err(e) => return Err(DatabaseKeyError::ChallengeResponseKeyError),
        };
        response.push(byte);
        hex_string_buffer = "".to_string();
    }
    // TODO should we handle an odd number of hex characters?

    Ok(response)
}
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut response: String = "".to_string();
    for byte in bytes {
        response += &format!("{:02X}", byte);
    }
    response
}

#[cfg(test)]
mod key_tests {

    use crate::error::DatabaseKeyError;

    use super::DatabaseKey;

    #[test]
    fn test_key() -> Result<(), DatabaseKeyError> {
        let ke = DatabaseKey::new()
            .with_password("asdf")
            .get_key_elements()?;
        assert_eq!(ke.len(), 1);

        let ke = DatabaseKey::new()
            .with_keyfile(&mut "bare-key-file".as_bytes())?
            .get_key_elements()?;
        assert_eq!(ke.len(), 1);

        let ke = DatabaseKey::new()
            .with_keyfile(&mut "0123456789ABCDEF0123456789ABCDEF".as_bytes())?
            .get_key_elements()?;
        assert_eq!(ke.len(), 1);

        let ke = DatabaseKey::new()
            .with_password("asdf")
            .with_keyfile(&mut "bare-key-file".as_bytes())?
            .get_key_elements()?;
        assert_eq!(ke.len(), 2);

        let ke = DatabaseKey::new()
            .with_keyfile(
                &mut "<KeyFile><Key><Data>0!23456789ABCDEF0123456789ABCDEF</Data></Key></KeyFile>"
                    .as_bytes(),
            )?
            .get_key_elements()?;
        assert_eq!(ke.len(), 1);

        let ke = DatabaseKey::new().with_keyfile(
            &mut "<KeyFile><Key><Data>NXyYiJMHg3ls+eBmjbAjWec9lcOToJiofbhNiFMTJMw=</Data></Key></KeyFile>".as_bytes(),
        )?
        .get_key_elements()?;
        assert_eq!(ke.len(), 1);

        // other XML files will just be hashed as a "bare" keyfile
        let ke = DatabaseKey::new()
            .with_keyfile(&mut "<Not><A><KeyFile></KeyFile></A></Not>".as_bytes())?
            .get_key_elements()?;

        assert_eq!(ke.len(), 1);

        assert!(DatabaseKey {
            password: None,
            keyfile: None,
            challenge_response_key: None,
            challenge_response_result: None,
        }
        .get_key_elements()
        .is_err());

        Ok(())
    }
}
