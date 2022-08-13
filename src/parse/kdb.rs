use crate::{
    config::OuterCipherSuite,
    crypt::kdf::Kdf,
    db::{Database, Entry, Group, Header, InnerHeader, Node, NodeRefMut, Value},
    result::{DatabaseIntegrityError, Error, Result},
};

use byteorder::{ByteOrder, LittleEndian};
use cipher::generic_array::GenericArray;

use std::{collections::HashMap, convert::TryInto, str};

#[derive(Debug)]
pub struct KDBHeader {
    // https://gist.github.com/lgg/e6ccc6e212d18dd2ecd8a8c116fb1e45
    pub version: u32,
    pub flags: u32,
    pub subversion: u32,
    pub master_seed: Vec<u8>,   // 16 bytes
    pub encryption_iv: Vec<u8>, // 16 bytes
    pub num_groups: u32,
    pub num_entries: u32,
    pub contents_hash: Vec<u8>,  // 32 bytes
    pub transform_seed: Vec<u8>, // 32 bytes
    pub transform_rounds: u32,
}

const HEADER_SIZE: usize = 4 + 4 + 4 + 4 + 16 + 16 + 4 + 4 + 32 + 32 + 4; // first 4 bytes are the KeePass magic

fn parse_header(data: &[u8]) -> Result<KDBHeader> {
    let (version, _, _) = crate::parse::get_kdbx_version(data)?;

    if version != 0xb54b_fb65 {
        return Err(DatabaseIntegrityError::InvalidKDBXVersion {
            version,
            file_major_version: 0,
            file_minor_version: 0,
        }
        .into());
    }

    if data.len() < HEADER_SIZE {
        return Err(DatabaseIntegrityError::InvalidFixedHeader { size: data.len() }.into());
    }

    Ok(KDBHeader {
        version,
        flags: LittleEndian::read_u32(&data[8..]),
        subversion: LittleEndian::read_u32(&data[12..]),
        master_seed: data[16..32].to_vec(),
        encryption_iv: data[32..48].to_vec(),
        num_groups: LittleEndian::read_u32(&data[48..]),
        num_entries: LittleEndian::read_u32(&data[52..]),
        contents_hash: data[56..88].to_vec(),
        transform_seed: data[88..120].to_vec(),
        transform_rounds: LittleEndian::read_u32(&data[120..]),
    })
}

fn from_utf8(data: &[u8]) -> Result<String> {
    Ok(str::from_utf8(data)
        .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?
        .trim_end_matches('\0')
        .to_owned())
}

fn ensure_length(field_type: u16, field_size: u32, expected_field_size: u32) -> Result<()> {
    if field_size != expected_field_size {
        Err(DatabaseIntegrityError::InvalidKDBFieldLength {
            field_type,
            field_size,
            expected_field_size,
        }
        .into())
    } else {
        Ok(())
    }
}

fn entry_name(field_type: u16) -> &'static str {
    match field_type {
        0x0004 => "Title",
        0x0005 => "URL",
        0x0006 => "UserName",
        0x0008 => "Additional",
        0x000d => "BinaryDesc",
        _ => {
            panic!("Unsupported field type!");
        }
    }
}

// Collapse the tail of a deque of Groups up to the given level
fn collapse_tail_groups(branch: &mut Vec<Group>, level: usize, root: &mut Group) {
    while level < branch.len() {
        let leaf = branch.pop().unwrap(); // guaranteed to be at least 1 element since 0 <= level < branch.len()
        let parent = match branch.last_mut() {
            Some(parent) => parent,
            None => root,
        };
        parent.children.push(Node::Group(leaf));
    }
}

// A map from a GroupId to a path identifying (by name) a group in the group tree.
type GidMap = HashMap<u32, Vec<String>>;

fn parse_groups(root: &mut Group, header_num_groups: u32, data: &mut &[u8]) -> Result<GidMap> {
    // Loop over group TLVs
    let mut gid_map: HashMap<u32, Vec<String>> = HashMap::new(); // the gid to group path map
    let mut branch: Vec<Group> = Vec::new(); // the current branch in the group tree
    let mut group: Group = Default::default(); // the current group (will be added as a leaf of the branch)
    let mut level: Option<u16> = None; // the current group's level
    let mut gid: Option<u32> = None; // the current group's id
    let mut group_path: Vec<String> = Vec::new(); // the current group path
    let mut num_groups = 0; // the total number of parsed groups
    while num_groups < header_num_groups as usize {
        // Read group TLV
        let field_type = LittleEndian::read_u16(&data[0..]);
        let field_size = LittleEndian::read_u32(&data[2..]);
        let field_value = &data[6..6 + field_size as usize];

        match field_type {
            0x0000 => {} // KeePass ignores this field type
            0x0001 => {
                // GroupId
                ensure_length(field_type, field_size, 4)?;
                gid = Some(LittleEndian::read_u32(field_value));
            }
            0x0002 => group.name = from_utf8(field_value)?, // GroupName
            0x0003..=0x0006 => {
                // Creation/LastMod/LastAccess/Expire
                ensure_length(field_type, field_size, 5)?;
            }
            0x0007 => {
                //ImageId
                ensure_length(field_type, field_size, 4)?;
            }
            0x0008 => {
                // Level
                ensure_length(field_type, field_size, 2)?;
                level = Some(LittleEndian::read_u16(field_value));
            }
            0x0009 => {
                // Flags
                ensure_length(field_type, field_size, 4)?;
            }
            0xffff => {
                ensure_length(field_type, field_size, 0)?;

                let level = level
                    .ok_or_else(|| Error::from(DatabaseIntegrityError::MissingKDBGroupLevel))?
                    as usize;

                // Update the current group tree branch (collapse previous sub-branch, initiate
                // current sub-branch)
                if level < branch.len() {
                    group_path.truncate(level);
                    collapse_tail_groups(&mut branch, level, root);
                }
                if level == branch.len() {
                    group_path.push(group.name.clone());
                    branch.push(group);
                } else {
                    // Level is beyond the current depth, missing intermediate levels?
                    return Err(DatabaseIntegrityError::InvalidKDBGroupLevel {
                        group_level: level as u16,
                        current_level: branch.len() as u16,
                    }
                    .into());
                }

                // Update the GroupId map and reset state for the next group
                let group_id =
                    gid.ok_or_else(|| Error::from(DatabaseIntegrityError::MissingKDBGroupId))?;
                gid_map.insert(group_id, group_path.clone());
                group = Default::default();
                gid = None;
                num_groups += 1;
            }
            _ => {
                return Err(DatabaseIntegrityError::InvalidKDBGroupFieldType { field_type }.into());
            }
        }

        *data = &data[6 + field_size as usize..];
    }
    if gid != None {
        return Err(DatabaseIntegrityError::IncompleteKDBGroup.into());
    }
    // Collapse last group tree branch into the root
    collapse_tail_groups(&mut branch, 0, root);

    Ok(gid_map)
}

fn parse_entries(
    root: &mut Group,
    gid_map: GidMap,
    header_num_entries: u32,
    data: &mut &[u8],
) -> Result<()> {
    // Loop over entry TLVs
    let mut entry: Entry = Default::default(); // the current entry
    let mut gid: Option<u32> = None; // the current entry's group id
    let mut num_entries = 0;
    while num_entries < header_num_entries {
        // Read entry TLV
        let field_type = LittleEndian::read_u16(&data[0..]);
        let field_size = LittleEndian::read_u32(&data[2..]);
        let field_value = &data[6..6 + field_size as usize];

        panic!("The Field type is {}", field_type);
        match field_type {
            0x0000 => {} // KeePass ignores this field type
            0x0001 => {
                // uuid
                println!("The Uuid is {}", from_utf8(field_value).unwrap());
                ensure_length(field_type, field_size, 16)?;
                entry.fields.insert(
                    String::from("Uuid"),
                    Value::Unprotected(from_utf8(field_value)?),
                );
            }
            0x0002 => {
                // GroupId
                ensure_length(field_type, field_size, 4)?;
                gid = Some(LittleEndian::read_u32(field_value));
            }
            0x0003 => {
                // ImageId
                ensure_length(field_type, field_size, 4)?;
            }
            0x0004 | 0x0005 | 0x0006 | 0x0008 | 0x000d => {
                // Title/URL/UserName/Additional/BinaryDesc
                entry.fields.insert(
                    String::from(entry_name(field_type)),
                    Value::Unprotected(from_utf8(field_value)?),
                );
            }
            0x0007 => {
                // Password
                entry.fields.insert(
                    String::from("Password"),
                    Value::Protected(from_utf8(field_value)?.into()),
                );
            }
            0x0009..=0x000c => {
                // Creation/LastMod/LastAccess/Expire
                ensure_length(field_type, field_size, 5)?;
            }
            0x000e => {
                // BinaryData
                entry.fields.insert(
                    String::from("BinaryData"),
                    Value::Bytes(field_value.to_vec()),
                );
            }
            0xffff => {
                ensure_length(field_type, field_size, 0)?;

                let group_id =
                    gid.ok_or_else(|| Error::from(DatabaseIntegrityError::MissingKDBGroupId))?;
                let group_path: Vec<&str> = gid_map
                    .get(&group_id)
                    .ok_or_else(|| {
                        Error::from(DatabaseIntegrityError::InvalidKDBGroupId { group_id })
                    })?
                    .into_iter()
                    .map(|v| v.as_str())
                    .collect();

                let group = root.get_mut(group_path.as_slice());
                let group = if let Some(NodeRefMut::Group(g)) = group {
                    g
                } else {
                    panic!("Follow group_path")
                };

                group.children.push(Node::Entry(entry));
                entry = Default::default();
                gid = None;
                num_entries += 1;
            }
            _ => {
                return Err(DatabaseIntegrityError::InvalidKDBEntryFieldType { field_type }.into());
            }
        }

        *data = &data[6 + field_size as usize..];
    }
    if gid != None {
        return Err(DatabaseIntegrityError::IncompleteKDBEntry.into());
    }

    Ok(())
}

fn parse_db(header: &KDBHeader, data: &[u8]) -> Result<Group> {
    let mut root = Group {
        name: "Root".to_owned(),
        children: Default::default(),
        expires: Default::default(),
        times: Default::default(),
    };

    let mut pos = &data[..];

    let gid_map = parse_groups(&mut root, header.num_groups, &mut pos)?;

    parse_entries(&mut root, gid_map, header.num_entries, &mut pos)?;

    Ok(root)
}

pub(crate) fn parse(data: &[u8], key_elements: &[Vec<u8>]) -> Result<Database> {
    let header = parse_header(data)?;

    // Rest of file after header is payload
    let payload_encrypted = &data[HEADER_SIZE..];

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = if key_elements.len() == 1 {
        let key_element: [u8; 32] = key_elements[0].try_into().unwrap();
        GenericArray::from(key_element) // single pass of SHA256, already done before the call to parse()
    } else {
        crate::crypt::calculate_sha256(&key_elements)? // second pass of SHA256
    };

    // KDF the same as for KDBX
    let transformed_key = crate::crypt::kdf::AesKdf {
        seed: header.transform_seed.clone(),
        rounds: header.transform_rounds as u64,
    }
    .transform_key(&composite_key)?;

    let master_key =
        crate::crypt::calculate_sha256(&[header.master_seed.as_ref(), &transformed_key])?;

    let cipher = if header.flags & 2 != 0 {
        OuterCipherSuite::AES256
    } else if header.flags & 8 != 0 {
        OuterCipherSuite::Twofish
    } else {
        return Err(DatabaseIntegrityError::InvalidFixedCipherID { cid: header.flags }.into());
    };

    // Decrypt payload
    let payload_padded = cipher
        .get_cipher(&master_key, header.encryption_iv.as_ref())?
        .decrypt(payload_encrypted)?;
    let padlen = payload_padded[payload_padded.len() - 1] as usize;
    let payload = &payload_padded[..payload_padded.len() - padlen];

    // Check if we decrypted correctly
    let hash = crate::crypt::calculate_sha256(&[&payload])?;
    if header.contents_hash != hash.as_slice() {
        return Err(Error::IncorrectKey);
    }

    let root_group = parse_db(&header, &payload)?;

    Ok(Database {
        header: Header::KDB(header),
        inner_header: InnerHeader::None,
        root: root_group,
    })
}
