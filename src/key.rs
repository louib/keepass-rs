use std::io::Read;
use std::error::Error;
use std::process::Command;

use base64::{engine::general_purpose as base64_engine, Engine as _};
use xml::name::OwnedName;
use xml::reader::{EventReader, XmlEvent};

use crate::{crypt::{calculate_sha256, SHA256_DIGEST}, error::DatabaseKeyError};

pub type KeyElements = Vec<Vec<u8>>;
pub type KeyElementsRef<'a> = Vec<&'a [u8]>;

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

fn parse_keyfile(buffer: &[u8]) -> Result<Vec<u8>, DatabaseKeyError> {
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

}
impl ChallengeResponseKey {
    pub async fn get_key_material(challenge: &str) -> Result<String, DatabaseKeyError> {
        Ok("".to_string())
    }

}

pub fn get_challenge_response_from_ykchal(challenge: &[u8], slot: usize) -> Result<String, DatabaseKeyError> {
    // TODO verify that the binary is available on the system.
    //
    let mut hex_challenge: String = "".to_string();
    for byte in challenge {
        hex_challenge += &format!("{:02X}", byte);
    }

    let mut command = Command::new("ykchalresp");
    command.arg(format!("-{}", slot));
    command.arg(hex_challenge);

    let output = command.output()?;

    if !output.status.success() {
        // let stderr = String::from_utf8(output.stderr).unwrap();
        return Err(DatabaseKeyError::ChallengeResponseKeyError);
    }

    match String::from_utf8(output.stdout) {
        Ok(o) => Ok(o),
        Err(_e) => Err(DatabaseKeyError::ChallengeResponseKeyError),
    }

}

/// A KeePass key, which might consist of a password and/or a keyfile
#[derive(Debug, Clone, Default)]
pub struct DatabaseKey {
    password: Option<String>,
    keyfile: Option<Vec<u8>>,
    challenge_response_key: Option<ChallengeResponseKey>,
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

    pub fn new() -> Self {
        Default::default()
    }

    pub(crate) fn get_key_elements(&self) -> Result<KeyElements, DatabaseKeyError> {
        // TODO raise an error if a challenge response key is defined?
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

        Ok(out)
    }

    pub(crate) fn challenge_response(self) -> Result<DatabaseKey, DatabaseKeyError> {
        if self.challenge_response_key.is_some() {

        }
        Ok(self)
    }

    pub(crate) fn get_key_digest(&self) -> Result<SHA256_DIGEST, DatabaseKeyError> {
        let key_elements: KeyElements = self.get_key_elements()?.clone();
        let key_elements: KeyElementsRef = key_elements.iter().map(|v| &v[..]).collect();
        match calculate_sha256(&key_elements) {
            Ok(d) => Ok(d),
            Err(e) => Err(DatabaseKeyError::Cryptography(e)),
        }
    }

    pub(crate) fn get_challenge_response_key_elements(self, challenge: &[u8]) -> Result<KeyElements, DatabaseKeyError> {
        let mut key_elements = self.get_key_elements()?;

        let response = get_challenge_response_from_ykchal(challenge, 2)?;
        key_elements.push(response.as_bytes().to_vec());

        return Ok(key_elements);
    }

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
        }
        .get_key_elements()
        .is_err());

        Ok(())
    }
}


