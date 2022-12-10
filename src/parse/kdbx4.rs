use uuid::Uuid;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;

use crate::{
    config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
    crypt,
    db::{Database, Entry, Group, Header, InnerHeader, Node},
    hmac_block_stream, key,
    result::{DatabaseIntegrityError, Error, Result},
    variant_dictionary::VariantDictionary,
    xml_parse,
};

use byteorder::{ByteOrder, LittleEndian};

#[derive(Debug)]
pub struct KDBX4Header {
    // https://gist.github.com/msmuenchen/9318327
    pub version: u32,
    pub file_major_version: u16,
    pub file_minor_version: u16,
    pub outer_cipher: OuterCipherSuite,
    pub compression: Compression,
    pub master_seed: Vec<u8>,
    pub outer_iv: Vec<u8>,
    pub kdf: KdfSettings,
}

pub const HEADER_MASTER_SEED_SIZE: u8 = 16;

pub const HEADER_END_ID: u8 = 0;
pub const HEADER_COMMENT_ID: u8 = 1;
pub const HEADER_OUTER_ENCRYPTION_ID: u8 = 2;
pub const HEADER_COMPRESSION_ID: u8 = 3;
pub const HEADER_MASTER_SEED_ID: u8 = 4;
pub const HEADER_ENCRYPTION_IV_ID: u8 = 7;
pub const HEADER_KDF_PARAMS_ID: u8 = 11;

pub const INNER_HEADER_END: u8 = 0;
/// The ID of the inner header random stream
pub const INNER_HEADER_RANDOM_STREAM: u8 = 1;
pub const INNER_HEADER_RANDOM_STREAM_KEY: u8 = 2;
pub const INNER_HEADER_BINARY_ATTACHMENTS: u8 = 3;

#[derive(Debug)]
pub struct BinaryAttachment {
    pub flags: u8,
    pub content: Vec<u8>,
}

impl TryFrom<&[u8]> for BinaryAttachment {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        let flags = data[0];
        let content = data[1..].to_vec();

        Ok(BinaryAttachment { flags, content })
    }
}
impl BinaryAttachment {
    fn dump(&self) -> Vec<u8> {
        let mut attachment: Vec<u8> = vec![self.flags];
        attachment.extend_from_slice(&self.content.clone());
        attachment
    }
}

#[derive(Debug)]
pub struct KDBX4InnerHeader {
    pub inner_random_stream: InnerCipherSuite,
    pub inner_random_stream_key: Vec<u8>,
    pub binaries: Vec<BinaryAttachment>,
}

// TODO move this to parse with get_kdbx_version.
fn dump_kdbx_version(header: &KDBX4Header) -> Result<Vec<u8>> {
    let mut header_data: Vec<u8> = vec![];
    header_data.extend_from_slice(&crate::parse::KDBX_IDENTIFIER);

    header_data.resize(12, 0);
    LittleEndian::write_u32(&mut header_data[4..8], header.version);
    LittleEndian::write_u16(&mut header_data[8..10], header.file_minor_version);
    LittleEndian::write_u16(&mut header_data[10..12], header.file_major_version);

    Ok(header_data)
}

// TODO move this to parse.
fn dump_outer_header(header: &KDBX4Header) -> Result<Vec<u8>> {
    let mut header_data: Vec<u8> = vec![];
    header_data.extend_from_slice(&dump_kdbx_version(header)?);

    write_header_field(
        &mut header_data,
        HEADER_OUTER_ENCRYPTION_ID,
        &header.outer_cipher.dump(),
    );

    write_header_field(
        &mut header_data,
        HEADER_COMPRESSION_ID,
        &header.compression.dump(),
    );

    write_header_field(&mut header_data, HEADER_ENCRYPTION_IV_ID, &header.outer_iv);

    write_header_field(&mut header_data, HEADER_MASTER_SEED_ID, &header.master_seed);

    let vd: VariantDictionary = header.kdf.dump();
    write_header_field(&mut header_data, HEADER_KDF_PARAMS_ID, &vd.dump()?);

    write_header_field(&mut header_data, HEADER_END_ID, &[]);

    Ok(header_data)
}

fn write_header_field(header_data: &mut Vec<u8>, field_id: u8, field_value: &[u8]) {
    header_data.push(field_id);
    let pos = header_data.len();
    header_data.resize(pos + 4, 0);
    LittleEndian::write_u32(
        &mut header_data[pos..pos + 4],
        field_value.len().try_into().unwrap(),
    );
    header_data.extend_from_slice(field_value);
}

fn parse_outer_header(data: &[u8]) -> Result<(KDBX4Header, usize)> {
    let (version, file_major_version, file_minor_version) = crate::parse::get_kdbx_version(data)?;

    if version != crate::db::KEEPASS_LATEST_ID || file_major_version != 4 {
        return Err(DatabaseIntegrityError::InvalidKDBXVersion {
            version,
            file_major_version,
            file_minor_version,
        }
        .into());
    }

    let mut outer_cipher: Option<OuterCipherSuite> = None;
    let mut compression: Option<Compression> = None;
    let mut master_seed: Option<Vec<u8>> = None;
    let mut outer_iv: Option<Vec<u8>> = None;
    let mut kdf: Option<KdfSettings> = None;

    // parse header
    let mut pos = 12;

    loop {
        // parse header blocks.
        //
        // every block is a triplet of (3 + entry_length) bytes with this structure:
        //
        // (
        //   entry_type: u8,                        // a numeric entry type identifier
        //   entry_length: u32,                     // length of the entry buffer
        //   entry_buffer: [u8; entry_length]       // the entry buffer
        // )

        let entry_type = data[pos];
        let entry_length: usize = LittleEndian::read_u32(&data[pos + 1..(pos + 5)]) as usize;
        let entry_buffer = &data[(pos + 5)..(pos + 5 + entry_length)];

        pos += 5 + entry_length;

        match entry_type {
            // Finished parsing header.
            HEADER_END_ID => {
                break;
            }

            HEADER_COMMENT_ID => {}

            // A UUID specifying which cipher suite
            // should be used to encrypt the payload
            HEADER_OUTER_ENCRYPTION_ID => {
                outer_cipher = Some(OuterCipherSuite::try_from(entry_buffer)?);
            }

            // First byte determines compression of payload
            HEADER_COMPRESSION_ID => {
                compression = Some(Compression::try_from(LittleEndian::read_u32(
                    &entry_buffer,
                ))?);
            }

            // Master seed for deriving the master key
            HEADER_MASTER_SEED_ID => master_seed = Some(entry_buffer.to_vec()),

            // Initialization Vector for decrypting the payload
            HEADER_ENCRYPTION_IV_ID => outer_iv = Some(entry_buffer.to_vec()),

            // KDF Parameters
            HEADER_KDF_PARAMS_ID => {
                let vd = VariantDictionary::parse(entry_buffer)?;
                kdf = Some(KdfSettings::try_from(vd)?);
            }

            _ => {
                return Err(DatabaseIntegrityError::InvalidOuterHeaderEntry { entry_type }.into());
            }
        };
    }

    // at this point, the header needs to be fully defined - unwrap options and return errors if
    // something is missing

    fn get_or_err<T>(v: Option<T>, err: &str) -> Result<T> {
        v.ok_or_else(|| {
            DatabaseIntegrityError::IncompleteOuterHeader {
                missing_field: err.into(),
            }
            .into()
        })
    }

    let outer_cipher = get_or_err(outer_cipher, "Outer Cipher ID")?;
    let compression = get_or_err(compression, "Compression ID")?;
    let master_seed = get_or_err(master_seed, "Master seed")?;
    let outer_iv = get_or_err(outer_iv, "Outer IV")?;

    let kdf = get_or_err(kdf, "Key Derivation Function Parameters")?;

    Ok((
        KDBX4Header {
            version,
            file_major_version,
            file_minor_version,
            outer_cipher,
            compression,
            master_seed,
            outer_iv,
            kdf,
        },
        pos,
    ))
}

fn parse_inner_header(data: &[u8]) -> Result<(KDBX4InnerHeader, usize)> {
    let mut pos = 0;

    let mut inner_random_stream = None;
    let mut inner_random_stream_key = None;
    let mut binaries = Vec::new();

    loop {
        let entry_type = data[pos];
        let entry_length: usize = LittleEndian::read_u32(&data[pos + 1..(pos + 5)]) as usize;
        let entry_buffer = &data[(pos + 5)..(pos + 5 + entry_length)];

        pos += 5 + entry_length;

        match entry_type {
            INNER_HEADER_END => break,

            INNER_HEADER_RANDOM_STREAM => {
                inner_random_stream = Some(InnerCipherSuite::try_from(LittleEndian::read_u32(
                    &entry_buffer,
                ))?);
            }

            INNER_HEADER_RANDOM_STREAM_KEY => inner_random_stream_key = Some(entry_buffer.to_vec()),

            INNER_HEADER_BINARY_ATTACHMENTS => {
                let binary = BinaryAttachment::try_from(entry_buffer)?;
                binaries.push(binary);
            }

            _ => {
                return Err(DatabaseIntegrityError::InvalidInnerHeaderEntry { entry_type }.into());
            }
        }
    }

    fn get_or_err<T>(v: Option<T>, err: &str) -> Result<T> {
        v.ok_or_else(|| {
            DatabaseIntegrityError::IncompleteInnerHeader {
                missing_field: err.into(),
            }
            .into()
        })
    }

    let inner_random_stream = get_or_err(inner_random_stream, "Inner random stream UUID")?;
    let inner_random_stream_key = get_or_err(inner_random_stream_key, "Inner random stream key")?;

    Ok((
        KDBX4InnerHeader {
            inner_random_stream,
            inner_random_stream_key,
            binaries,
        },
        pos,
    ))
}

fn dump_inner_header(inner_header: &KDBX4InnerHeader) -> Result<Vec<u8>> {
    let mut header_data: Vec<u8> = vec![];

    let mut random_stream_data: Vec<u8> = vec![];
    random_stream_data.resize(4, 0);
    LittleEndian::write_u32(
        &mut random_stream_data[0..4],
        inner_header.inner_random_stream.dump(),
    );
    write_header_field(
        &mut header_data,
        INNER_HEADER_RANDOM_STREAM,
        &random_stream_data,
    );

    write_header_field(
        &mut header_data,
        INNER_HEADER_RANDOM_STREAM_KEY,
        &inner_header.inner_random_stream_key,
    );

    for binary in &inner_header.binaries {
        write_header_field(
            &mut header_data,
            INNER_HEADER_BINARY_ATTACHMENTS,
            &binary.dump(),
        );
    }

    write_header_field(&mut header_data, INNER_HEADER_END, &[]);

    Ok(header_data)
}

/// Dump a KeePass database using the key elements
pub fn dump(db: &Database, key_elements: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut data: Vec<u8> = vec![];

    let header = match &db.header {
        Header::KDBX4(h) => h,
        _ => {
            return Err(Error::Unsupported(
                "Invalid header format for dumping kdbx4.".to_string(),
            ))
        }
    };

    let header_data = dump_outer_header(&header)?;
    data.extend_from_slice(&header_data);

    let header_sha256 = crypt::calculate_sha256(&[&header_data])?;
    data.extend_from_slice(&header_sha256);

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = crypt::calculate_sha256(&key_elements)?;
    let transformed_key = header.kdf.get_kdf().transform_key(&composite_key)?;
    let master_key = crypt::calculate_sha256(&[header.master_seed.as_ref(), &transformed_key])?;

    // verify credentials
    let hmac_key = crypt::calculate_sha512(&[&header.master_seed, &transformed_key, b"\x01"])?;
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(usize::max_value(), &hmac_key)?;
    let header_hmac = crypt::calculate_hmac(&[&header_data], &header_hmac_key)?;
    data.extend_from_slice(&header_hmac);

    let mut payload: Vec<u8> = vec![];
    let inner_header = match &db.inner_header {
        InnerHeader::KDBX4(h) => h,
        _ => {
            return Err(Error::Unsupported(
                "Invalid header format for dumping kdbx4.".to_string(),
            ))
        }
    };
    let inner_header_data = dump_inner_header(&inner_header)?;
    payload.extend_from_slice(&inner_header_data);

    // Initialize inner decryptor from inner header params
    let mut inner_cipher = inner_header
        .inner_random_stream
        .get_cipher(&inner_header.inner_random_stream_key)?;

    // after inner header is one XML document
    let xml = xml_parse::dump_database(&db, &mut *inner_cipher)?;
    payload.extend_from_slice(&xml);

    let payload_compressed = header.compression.get_compression().compress(&payload)?;

    let payload_encrypted = header
        .outer_cipher
        .get_cipher(&master_key, header.outer_iv.as_ref())?
        .encrypt(&payload_compressed)?;

    let payload_hmac = hmac_block_stream::write_hmac_block_stream(&payload_encrypted, &hmac_key)?;
    data.extend_from_slice(&payload_hmac);

    Ok(data)
}

/// Open, decrypt and parse a KeePass database from a source and key elements
pub fn parse(data: &[u8], key_elements: &[Vec<u8>]) -> Result<Database> {
    let (header, inner_header, xml) = decrypt_xml(data, key_elements)?;

    // Initialize inner decryptor from inner header params
    let mut inner_decryptor = inner_header
        .inner_random_stream
        .get_cipher(&inner_header.inner_random_stream_key)?;

    let (root, deleted_objects) = xml_parse::parse_xml_block(&xml, &mut *inner_decryptor)?;

    let db = Database {
        header: Header::KDBX4(header),
        inner_header: InnerHeader::KDBX4(inner_header),
        root,
        name: None,
        deleted_objects,
    };

    Ok(db)
}

/// Open and decrypt a KeePass KDBX4 database from a source and key elements
pub(crate) fn decrypt_xml(
    data: &[u8],
    key_elements: &[Vec<u8>],
) -> Result<(KDBX4Header, KDBX4InnerHeader, Vec<u8>)> {
    // parse header
    let (header, body_start) = parse_outer_header(data)?;

    // split file into segments:
    //      header_data         - The outer header data
    //      header_sha256       - A Sha256 hash of header_data (for verification of header integrity)
    //      header_hmac         - A HMAC of the header_data (for verification of the key_elements)
    //      hmac_block_stream   - A HMAC-verified block stream of encrypted and compressed blocks
    let header_data = &data[0..body_start];
    let header_sha256 = &data[body_start..(body_start + 32)];
    let header_hmac = &data[(body_start + 32)..(body_start + 64)];
    let hmac_block_stream = &data[(body_start + 64)..];

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = crypt::calculate_sha256(&key_elements)?;
    let transformed_key = header.kdf.get_kdf().transform_key(&composite_key)?;
    let master_key = crypt::calculate_sha256(&[header.master_seed.as_ref(), &transformed_key])?;

    // verify header
    if header_sha256 != crypt::calculate_sha256(&[&data[0..body_start]])?.as_slice() {
        return Err(DatabaseIntegrityError::HeaderHashMismatch.into());
    }

    // verify credentials
    let hmac_key = crypt::calculate_sha512(&[&header.master_seed, &transformed_key, b"\x01"])?;
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(usize::max_value(), &hmac_key)?;
    if header_hmac != crypt::calculate_hmac(&[header_data], &header_hmac_key)?.as_slice() {
        return Err(Error::IncorrectKey);
    }

    // read encrypted payload from hmac-verified block stream
    let payload_encrypted =
        hmac_block_stream::read_hmac_block_stream(&hmac_block_stream, &hmac_key)?;

    // Decrypt and decompress encrypted payload
    let payload_compressed = header
        .outer_cipher
        .get_cipher(&master_key, header.outer_iv.as_ref())?
        .decrypt(&payload_encrypted)?;

    let payload = header
        .compression
        .get_compression()
        .decompress(&payload_compressed)?;

    // KDBX4 has inner header, too - parse it
    let (inner_header, xml_start) = parse_inner_header(&payload)?;

    // after inner header is one XML document
    let xml = &payload[xml_start..];
    // panic!("{:?}", std::str::from_utf8(&xml));

    Ok((header, inner_header, xml.to_vec()))
}

pub fn create_database(
    outer_cipher_suite: OuterCipherSuite,
    compression: Compression,
    inner_cipher_suite: InnerCipherSuite,
    kdf_setting: KdfSettings,
    root: Group,
    binaries: Vec<BinaryAttachment>,
) -> Database {
    let mut outer_iv: Vec<u8> = vec![];
    outer_iv.resize(outer_cipher_suite.get_nonce_size().into(), 0);
    getrandom::getrandom(&mut outer_iv);

    let mut inner_random_stream_key: Vec<u8> = vec![];
    inner_random_stream_key.resize(inner_cipher_suite.get_nonce_size().into(), 0);
    getrandom::getrandom(&mut inner_random_stream_key);

    let mut kdf: KdfSettings;
    let mut kdf_seed: Vec<u8> = vec![];
    kdf_seed.resize(kdf_setting.seed_size().into(), 0);
    getrandom::getrandom(&mut kdf_seed);

    let mut master_seed: Vec<u8> = vec![];
    master_seed.resize(crate::parse::kdbx4::HEADER_MASTER_SEED_SIZE.into(), 0);
    getrandom::getrandom(&mut master_seed);

    match kdf_setting {
        KdfSettings::Aes { rounds, .. } => {
            // FIXME obviously this is ugly. We should be able to change
            // the seed in the first kdf object.
            kdf = KdfSettings::Aes {
                seed: kdf_seed,
                rounds,
            };
        }
        KdfSettings::Argon2 { .. } => {
            kdf = KdfSettings::Argon2 {
                salt: kdf_seed,
                iterations: 100,
                memory: 1000000,
                parallelism: 1,
                version: argon2::Version::Version13,
            };
        }
    };

    Database {
        header: Header::KDBX4(KDBX4Header {
            version: crate::db::KEEPASS_LATEST_ID,
            file_major_version: 4,
            file_minor_version: 3,
            outer_cipher: outer_cipher_suite,
            compression,
            master_seed,
            outer_iv,
            kdf,
        }),
        inner_header: InnerHeader::KDBX4(KDBX4InnerHeader {
            inner_random_stream: inner_cipher_suite,
            inner_random_stream_key,
            binaries,
        }),
        root,
        name: None,
        deleted_objects: vec![],
    }
}
