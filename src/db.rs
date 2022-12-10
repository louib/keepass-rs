use secstr::SecStr;
use std::collections::{HashMap, VecDeque};
use uuid::Uuid;

use crate::{
    crypt, key,
    parse::{
        kdb::KDBHeader,
        kdbx3::KDBX3Header,
        kdbx4::{KDBX4Header, KDBX4InnerHeader},
    },
    result::{DatabaseIntegrityError, Error, Result},
};

#[derive(Debug)]
pub enum Header {
    KDB(KDBHeader),
    KDBX3(KDBX3Header),
    KDBX4(KDBX4Header),
}

#[derive(Debug)]
pub enum InnerHeader {
    None,
    KDBX4(KDBX4InnerHeader),
}

/// An item (group or entry) that was deleted from
/// the database completely.
#[derive(Debug)]
pub struct DeletedObject {
    /// The unique identifier of the deleted object.
    pub uuid: String,

    pub deletion_time: chrono::NaiveDateTime,
}

/// A decrypted KeePass database
#[derive(Debug)]
pub struct Database {
    /// Header information of the KeePass database
    pub header: Header,

    /// Optional inner header information
    pub inner_header: InnerHeader,

    /// Root node of the KeePass database
    pub root: Group,

    /// The name of the database.
    pub name: Option<String>,

    pub deleted_objects: Vec<DeletedObject>,
}

/// Identifier for KeePass 1 format.
pub const KEEPASS_1_ID: u32 = 0xb54bfb65;
/// Identifier for KeePass 2 pre-release format.
pub const KEEPASS_2_ID: u32 = 0xb54bfb66;
/// Identifier for the latest KeePass formats.
pub const KEEPASS_LATEST_ID: u32 = 0xb54bfb67;

impl Database {
    /// Save a database to a std::io::Write
    pub fn save(
        &self,
        destination: &mut dyn std::io::Write,
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<()> {
        let key_elements = key::get_key_elements(password, keyfile)?;

        let data = match self.header {
            Header::KDB(_) => {
                return Err(crate::result::Error::Unsupported(
                    "saving KDB version 1".to_string(),
                ))
            }
            Header::KDBX3(_) => {
                return Err(crate::result::Error::Unsupported(
                    "saving KDB version 3".to_string(),
                ))
            }
            Header::KDBX4(_) => crate::parse::kdbx4::dump(self, &key_elements),
        }?;

        destination.write_all(&data)?;
        Ok(())
    }

    /// Parse a database from a std::io::Read
    pub fn open(
        source: &mut dyn std::io::Read,
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<Database> {
        let key_elements = key::get_key_elements(password, keyfile)?;

        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let (version, file_major_version, file_minor_version) =
            crate::parse::get_kdbx_version(data.as_ref())?;

        match version {
            KEEPASS_1_ID => crate::parse::kdb::parse(data.as_ref(), &key_elements),
            // KEEPASS_2_ID => alpha/beta kbd 2.x
            KEEPASS_LATEST_ID if file_major_version == 3 => {
                crate::parse::kdbx3::parse(data.as_ref(), &key_elements)
            }
            KEEPASS_LATEST_ID if file_major_version == 4 => {
                crate::parse::kdbx4::parse(data.as_ref(), &key_elements)
            }
            _ => Err(DatabaseIntegrityError::InvalidKDBXVersion {
                version,
                file_major_version,
                file_minor_version,
            }
            .into()),
        }
    }

    /// Helper function to load a database into its internal XML chunks
    pub fn get_xml_chunks(
        source: &mut dyn std::io::Read,
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<Vec<Vec<u8>>> {
        let mut key_elements = key::get_key_elements(password, keyfile)?;

        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let (version, file_major_version, file_minor_version) =
            crate::parse::get_kdbx_version(data.as_ref())?;

        let data = match version {
            KEEPASS_1_ID => panic!("Dumping XML from KDB databases not supported"),
            // KEEPASS_2_ID => alpha/beta kbd 2.x
            KEEPASS_LATEST_ID if file_major_version == 3 => {
                crate::parse::kdbx3::decrypt_xml(data.as_ref(), &key_elements)?.1
            }
            KEEPASS_LATEST_ID if file_major_version == 4 => {
                vec![crate::parse::kdbx4::decrypt_xml(data.as_ref(), &key_elements)?.2]
            }
            _ => {
                return Err(Error::DatabaseIntegrity {
                    e: DatabaseIntegrityError::InvalidKDBXVersion {
                        version,
                        file_major_version,
                        file_minor_version,
                    },
                })
            }
        };

        Ok(data)
    }
}

/// A database group with child groups and entries
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Group {
    /// The unique identifier of the group
    pub uuid: String,

    /// The name of the group
    pub name: String,

    /// The list of child nodes (Groups or Entries)
    pub children: Vec<Node>,

    /// The list of time fields for this group
    ///
    /// Using chrono::NaiveDateTime which does not include timezone
    /// or UTC offset because KeePass clients typically store timestamps
    /// relative to the local time on the machine writing the data without
    /// including accurate UTC offset or timezone information.
    pub times: HashMap<String, chrono::NaiveDateTime>,

    /// Does this group expire
    pub expires: bool,

    /// Notes associated with the group
    pub notes: String,
}

impl Group {
    /// Recursively get a Group or Entry reference by specifying a path relative to the current Group
    /// ```
    /// use keepass::{Database, NodeRef};
    /// use std::{fs::File, path::Path};
    ///
    /// let path = Path::new("tests/resources/test_db_with_password.kdbx");
    /// let db = Database::open(&mut File::open(path).unwrap(), Some("demopass"), None).unwrap();
    ///
    /// if let Some(NodeRef::Entry(e)) = db.root.get(&["General", "Sample Entry #2"]) {
    ///     println!("User: {}", e.get_username().unwrap());
    /// }
    /// ```
    pub fn get<'a>(&'a self, path: &[&str]) -> Option<NodeRef<'a>> {
        if path.is_empty() {
            Some(NodeRef::Group(self))
        } else {
            if path.len() == 1 {
                let head = path[0];
                self.children
                    .iter()
                    .filter_map(|n| match n {
                        Node::Group(_) => None,
                        Node::Entry(e) => {
                            e.get_title()
                                .and_then(|t| if t == head { Some(n.to_ref()) } else { None })
                        }
                    })
                    .next()
            } else {
                let head = path[0];
                let tail = &path[1..path.len()];

                let head_group = self
                    .children
                    .iter()
                    .filter_map(|n| match n {
                        Node::Group(g) if g.name == head => Some(g),
                        _ => None,
                    })
                    .next()?;

                head_group.get(tail)
            }
        }
    }

    /// Recursively get a mutable reference to a Group or Entry by specifying a path relative to
    /// the current Group
    pub fn get_mut<'a>(&'a mut self, path: &[&str]) -> Option<NodeRefMut<'a>> {
        if path.is_empty() {
            Some(NodeRefMut::Group(self))
        } else {
            if path.len() == 1 {
                let head = path[0];
                self.children
                    .iter_mut()
                    .filter(|n| match n {
                        Node::Group(g) => g.name == head,
                        Node::Entry(e) => e.get_title().map(|t| t == head).unwrap_or(false),
                    })
                    .map(|t| t.to_ref_mut())
                    .next()
            } else {
                let head = path[0];
                let tail = &path[1..path.len()];

                let head_group: &mut Group = self
                    .children
                    .iter_mut()
                    .filter_map(|n| match n {
                        Node::Group(g) if g.name == head => Some(g),
                        _ => None,
                    })
                    .next()?;

                head_group.get_mut(tail)
            }
        }
    }

    /// Get a timestamp field by name
    ///
    /// Returning the chrono::NaiveDateTime which does not include timezone
    /// or UTC offset because KeePass clients typically store timestamps
    /// relative to the local time on the machine writing the data without
    /// including accurate UTC offset or timezone information.
    pub fn get_time(&self, key: &str) -> Option<&chrono::NaiveDateTime> {
        self.times.get(key)
    }

    /// Convenience method for getting the value of the 'ExpiryTime' timestamp
    pub fn get_expiry_time(&self) -> Option<&chrono::NaiveDateTime> {
        self.get_time("ExpiryTime")
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Value {
    Bytes(Vec<u8>),
    Unprotected(String),
    Protected(SecStr),
}

/// An AutoType setting associated with an Entry
#[derive(Debug, Default, Eq, PartialEq)]
pub struct AutoType {
    pub enabled: bool,
    pub sequence: Option<String>,
    pub associations: Vec<AutoTypeAssociation>,
}

/// A window association associated with an AutoType setting
#[derive(Debug, Default, Eq, PartialEq)]
pub struct AutoTypeAssociation {
    pub window: Option<String>,
    pub sequence: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Node {
    Group(Group),
    Entry(Entry),
}

impl Node {
    pub fn to_ref<'a>(&'a self) -> NodeRef<'a> {
        self.into()
    }

    pub fn to_ref_mut<'a>(&'a mut self) -> NodeRefMut<'a> {
        self.into()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum NodeRef<'a> {
    Group(&'a Group),
    Entry(&'a Entry),
}

impl<'a> std::convert::From<&'a Node> for NodeRef<'a> {
    fn from(n: &'a Node) -> Self {
        match n {
            Node::Group(g) => NodeRef::Group(g),
            Node::Entry(e) => NodeRef::Entry(e),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum NodeRefMut<'a> {
    Group(&'a mut Group),
    Entry(&'a mut Entry),
}

impl<'a> std::convert::From<&'a mut Node> for NodeRefMut<'a> {
    fn from(n: &'a mut Node) -> Self {
        match n {
            Node::Group(g) => NodeRefMut::Group(g),
            Node::Entry(e) => NodeRefMut::Entry(e),
        }
    }
}

/// A database entry containing several key-value fields.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Entry {
    pub uuid: String,
    pub fields: HashMap<String, Value>,
    pub autotype: Option<AutoType>,
    pub expires: bool,
    pub times: HashMap<String, chrono::NaiveDateTime>,
    pub tags: Vec<String>,
}
impl Entry {
    pub fn new() -> Entry {
        Entry {
            uuid: Uuid::new_v4().to_string(),
            fields: HashMap::default(),
            times: HashMap::default(),
            expires: false,
            autotype: None,
            tags: vec![],
        }
    }
}

pub const ROOT_GROUP_NAME: &str = "Root";

pub const USERNAME_FIELD_NAME: &str = "UserName";
pub const AUTOTYPE_FIELD_NAME: &str = "AutoType";
pub const EXPIRY_TIME_FIELD_NAME: &str = "ExpiryTime";
pub const TITLE_FIELD_NAME: &str = "Title";
pub const TAGS_FIELD_NAME: &str = "Tags";
pub const PASSWORD_FIELD_NAME: &str = "Password";
pub const NOTES_FIELD_NAME: &str = "Notes";
pub const UUID_FIELD_NAME: &str = "UUID";

impl<'a> Entry {
    /// Get a field by name, taking care of unprotecting Protected values automatically
    pub fn get(&'a self, key: &str) -> Option<&'a str> {
        match self.fields.get(key) {
            Some(&Value::Bytes(_)) => None,
            Some(&Value::Protected(ref pv)) => std::str::from_utf8(pv.unsecure()).ok(),
            Some(&Value::Unprotected(ref uv)) => Some(&uv),
            None => None,
        }
    }

    /// Get a bytes field by name
    pub fn get_bytes(&'a self, key: &str) -> Option<&'a [u8]> {
        match self.fields.get(key) {
            Some(&Value::Bytes(ref b)) => Some(&b),
            Some(&Value::Protected(_)) => None,
            Some(&Value::Unprotected(_)) => None,
            None => None,
        }
    }

    pub fn get_uuid(&'a self) -> &'a str {
        &self.uuid
    }

    /// Get a timestamp field by name
    ///
    /// Returning the chrono::NaiveDateTime which does not include timezone
    /// or UTC offset because KeePass clients typically store timestamps
    /// relative to the local time on the machine writing the data without
    /// including accurate UTC offset or timezone information.
    pub fn get_time(&self, key: &str) -> Option<&chrono::NaiveDateTime> {
        self.times.get(key)
    }

    /// Convenience method for getting the value of the 'ExpiryTime' timestamp
    /// This value is usually only meaningful/useful when expires == true
    pub fn get_expiry_time(&self) -> Option<&chrono::NaiveDateTime> {
        self.get_time(EXPIRY_TIME_FIELD_NAME)
    }

    /// Convenience method for getting the value of the 'Title' field
    pub fn get_title(&'a self) -> Option<&'a str> {
        self.get("Title")
    }

    /// Convenience method for getting the value of the 'UserName' field
    pub fn get_username(&'a self) -> Option<&'a str> {
        self.get("UserName")
    }

    /// Convenience method for getting the value of the 'Password' field
    pub fn get_password(&'a self) -> Option<&'a str> {
        self.get("Password")
    }
}

/// An iterator over Groups and Entries
pub struct NodeIter<'a> {
    queue: VecDeque<NodeRef<'a>>,
}

impl<'a> Iterator for NodeIter<'a> {
    type Item = NodeRef<'a>;

    fn next(&mut self) -> Option<NodeRef<'a>> {
        let head = self.queue.pop_front()?;

        if let NodeRef::Group(ref g) = head {
            self.queue.extend(g.children.iter().map(|n| n.into()))
        }

        Some(head)
    }
}

impl Group {
    pub fn new(name: &str) -> Group {
        Group {
            children: vec![],
            name: name.to_string(),
            uuid: Uuid::new_v4().to_string(),
            times: HashMap::default(),
            expires: false,
            notes: "".to_string(),
        }
    }
}

impl<'a> Group {
    pub fn iter(&'a self) -> NodeIter<'a> {
        (&self).into_iter()
    }
}

impl<'a> IntoIterator for &'a Group {
    type Item = NodeRef<'a>;
    type IntoIter = NodeIter<'a>;

    fn into_iter(self) -> NodeIter<'a> {
        let mut queue: VecDeque<NodeRef> = VecDeque::new();
        queue.push_back(NodeRef::Group(self));

        NodeIter { queue }
    }
}
