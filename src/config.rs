use hex_literal::hex;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;

use crate::crypt::ciphers::Cipher;
use crate::{
    compression, crypt,
    result::{DatabaseIntegrityError, Error, Result},
    variant_dictionary::{VariantDictionary, VariantDictionaryValue},
};

const _CIPHERSUITE_AES128: [u8; 16] = hex!("61ab05a1946441c38d743a563df8dd35");
const CIPHERSUITE_AES256: [u8; 16] = hex!("31c1f2e6bf714350be5805216afc5aff");
const CIPHERSUITE_TWOFISH: [u8; 16] = hex!("ad68f29f576f4bb9a36ad47af965346c");
const CIPHERSUITE_CHACHA20: [u8; 16] = hex!("d6038a2b8b6f4cb5a524339a31dbb59a");

#[derive(Debug)]
pub enum OuterCipherSuite {
    AES256,
    Twofish,
    ChaCha20,
}

impl OuterCipherSuite {
    pub(crate) fn get_cipher(
        &self,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Box<dyn crypt::ciphers::Cipher>> {
        match self {
            OuterCipherSuite::AES256 => Ok(Box::new(crypt::ciphers::AES256Cipher::new(key, iv)?)),
            OuterCipherSuite::Twofish => Ok(Box::new(crypt::ciphers::TwofishCipher::new(key, iv)?)),
            OuterCipherSuite::ChaCha20 => Ok(Box::new(crypt::ciphers::ChaCha20Cipher::new_key_iv(
                key, iv,
            )?)),
        }
    }

    pub fn get_nonce_size(&self) -> u8 {
        match self {
            OuterCipherSuite::AES256 => crypt::ciphers::AES256Cipher::nonce_size(),
            OuterCipherSuite::Twofish => crypt::ciphers::TwofishCipher::nonce_size(),
            OuterCipherSuite::ChaCha20 => crypt::ciphers::ChaCha20Cipher::nonce_size(),
        }
    }

    pub(crate) fn dump(&self) -> [u8; 16] {
        match self {
            OuterCipherSuite::AES256 => CIPHERSUITE_AES256,
            OuterCipherSuite::Twofish => CIPHERSUITE_TWOFISH,
            OuterCipherSuite::ChaCha20 => CIPHERSUITE_CHACHA20,
        }
    }
}

impl TryFrom<&[u8]> for OuterCipherSuite {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<OuterCipherSuite> {
        if v == CIPHERSUITE_AES256 {
            Ok(OuterCipherSuite::AES256)
        } else if v == CIPHERSUITE_TWOFISH {
            Ok(OuterCipherSuite::Twofish)
        } else if v == CIPHERSUITE_CHACHA20 {
            Ok(OuterCipherSuite::ChaCha20)
        } else {
            Err(DatabaseIntegrityError::InvalidOuterCipherID { cid: v.to_vec() }.into())
        }
    }
}

const PLAIN: u32 = 0;
const SALSA_20: u32 = 2;
const CHA_CHA_20: u32 = 3;

#[derive(Debug)]
pub enum InnerCipherSuite {
    Plain,
    Salsa20,
    ChaCha20,
}

impl InnerCipherSuite {
    pub(crate) fn get_cipher(&self, key: &[u8]) -> Result<Box<dyn crypt::ciphers::Cipher>> {
        match self {
            InnerCipherSuite::Plain => Ok(Box::new(crypt::ciphers::PlainCipher::new(key)?)),
            InnerCipherSuite::Salsa20 => Ok(Box::new(crypt::ciphers::Salsa20Cipher::new(key)?)),
            InnerCipherSuite::ChaCha20 => Ok(Box::new(crypt::ciphers::ChaCha20Cipher::new(key)?)),
        }
    }
    pub(crate) fn dump(&self) -> u32 {
        match self {
            InnerCipherSuite::Plain => PLAIN,
            InnerCipherSuite::Salsa20 => SALSA_20,
            InnerCipherSuite::ChaCha20 => CHA_CHA_20,
        }
    }
    pub fn get_nonce_size(&self) -> u8 {
        match self {
            InnerCipherSuite::Plain => crypt::ciphers::PlainCipher::nonce_size(),
            InnerCipherSuite::Salsa20 => crypt::ciphers::Salsa20Cipher::nonce_size(),
            InnerCipherSuite::ChaCha20 => crypt::ciphers::ChaCha20Cipher::nonce_size(),
        }
    }
}

impl TryFrom<u32> for InnerCipherSuite {
    type Error = Error;

    fn try_from(v: u32) -> Result<InnerCipherSuite> {
        match v {
            PLAIN => Ok(InnerCipherSuite::Plain),
            SALSA_20 => Ok(InnerCipherSuite::Salsa20),
            CHA_CHA_20 => Ok(InnerCipherSuite::ChaCha20),
            _ => Err(DatabaseIntegrityError::InvalidInnerCipherID { cid: v }.into()),
        }
    }
}

#[derive(Debug)]
pub enum KdfSettings {
    Aes {
        seed: Vec<u8>,
        rounds: u64,
    },
    Argon2 {
        salt: Vec<u8>,
        iterations: u64,
        memory: u64,
        parallelism: u32,
        version: argon2::Version,
    },
}

impl KdfSettings {
    pub fn seed_size(&self) -> u8 {
        match self {
            KdfSettings::Aes { seed, rounds } => 32,
            KdfSettings::Argon2 {
                salt,
                memory,
                iterations,
                parallelism,
                version,
            } => 32,
        }
    }
    pub(crate) fn get_kdf(&self) -> Box<dyn crypt::kdf::Kdf> {
        match self {
            KdfSettings::Aes { seed, rounds } => Box::new(crypt::kdf::AesKdf {
                seed: seed.clone(),
                rounds: *rounds,
            }),
            KdfSettings::Argon2 {
                memory,
                salt,
                iterations,
                parallelism,
                version,
            } => Box::new(crypt::kdf::Argon2Kdf {
                memory: *memory,
                salt: salt.clone(),
                iterations: *iterations,
                parallelism: *parallelism,
                version: *version,
            }),
        }
    }

    pub(crate) fn dump(&self) -> VariantDictionary {
        let mut data: HashMap<String, VariantDictionaryValue> = HashMap::new();

        match self {
            KdfSettings::Aes { seed, rounds } => {
                // FIXME this will always dump in KDBX4 format. Is this fine?
                data.insert(
                    "$UUID".to_string(),
                    VariantDictionaryValue::ByteArray(KDF_AES_KDBX4.to_vec()),
                );
                data.insert(
                    "R".to_string(),
                    VariantDictionaryValue::UInt64(rounds.clone()),
                );
                data.insert(
                    "S".to_string(),
                    VariantDictionaryValue::ByteArray(seed.to_vec()),
                );
            }
            KdfSettings::Argon2 {
                memory,
                salt,
                iterations,
                parallelism,
                version,
            } => {
                data.insert(
                    "$UUID".to_string(),
                    VariantDictionaryValue::ByteArray(KDF_ARGON2.to_vec()),
                );
                data.insert(
                    "M".to_string(),
                    VariantDictionaryValue::UInt64(memory.clone()),
                );
                data.insert(
                    "S".to_string(),
                    VariantDictionaryValue::ByteArray(salt.to_vec()),
                );
                data.insert(
                    "I".to_string(),
                    VariantDictionaryValue::UInt64(iterations.clone()),
                );
                data.insert(
                    "P".to_string(),
                    VariantDictionaryValue::UInt32(parallelism.clone()),
                );
                match version {
                    argon2::Version::Version10 => {
                        data.insert("V".to_string(), VariantDictionaryValue::UInt32(0x10));
                    }
                    argon2::Version::Version13 => {
                        data.insert("V".to_string(), VariantDictionaryValue::UInt32(0x13));
                    }
                }
            }
        }
        VariantDictionary { data }
    }
}

const KDF_AES_KDBX3: [u8; 16] = hex!("c9d9f39a628a4460bf740d08c18a4fea");
const KDF_AES_KDBX4: [u8; 16] = hex!("7c02bb8279a74ac0927d114a00648238");
const KDF_ARGON2: [u8; 16] = hex!("ef636ddf8c29444b91f7a9a403e30a0c");

impl TryFrom<VariantDictionary> for KdfSettings {
    type Error = Error;

    fn try_from(vd: VariantDictionary) -> Result<KdfSettings> {
        let uuid: Vec<u8> = vd.get("$UUID")?;

        if uuid == KDF_ARGON2 {
            let memory: u64 = vd.get("M")?;
            let salt: Vec<u8> = vd.get("S")?;
            let iterations: u64 = vd.get("I")?;
            let parallelism: u32 = vd.get("P")?;
            let version: u32 = vd.get("V")?;

            let version = match version {
                0x10 => argon2::Version::Version10,
                0x13 => argon2::Version::Version13,
                _ => {
                    return Err(Error::from(DatabaseIntegrityError::InvalidKDFVersion {
                        version,
                    }))
                }
            };

            Ok(KdfSettings::Argon2 {
                memory,
                salt,
                iterations,
                parallelism,
                version,
            })
        } else if uuid == KDF_AES_KDBX4 || uuid == KDF_AES_KDBX3 {
            let rounds: u64 = vd.get("R")?;
            let seed: Vec<u8> = vd.get("S")?;

            Ok(KdfSettings::Aes { rounds, seed })
        } else {
            Err(DatabaseIntegrityError::InvalidKDFUUID { uuid }.into())
        }
    }
}

#[derive(Debug)]
pub enum Compression {
    None,
    GZip,
}

impl Compression {
    pub(crate) fn get_compression(&self) -> Box<dyn compression::Decompress> {
        match self {
            Compression::None => Box::new(compression::NoCompression),
            Compression::GZip => Box::new(compression::GZipCompression),
        }
    }

    pub(crate) fn dump(&self) -> [u8; 4] {
        match self {
            Compression::None => [0, 0, 0, 0],
            Compression::GZip => [1, 0, 0, 0],
        }
    }
}

impl TryFrom<u32> for Compression {
    type Error = Error;

    fn try_from(v: u32) -> Result<Compression> {
        match v {
            0 => Ok(Compression::None),
            1 => Ok(Compression::GZip),
            _ => Err(DatabaseIntegrityError::InvalidCompressionSuite { cid: v }.into()),
        }
    }
}
