use crate::crypt::ciphers::Cipher;
use crate::result::{DatabaseIntegrityError, Error, Result};

use secstr::SecStr;

use xml::name::OwnedName;
use xml::reader::{EventReader, XmlEvent};
use xml::writer::{EmitterConfig, EventWriter, Result as XmlResult, XmlEvent as WriterEvent};

use super::db::{
    AutoType, AutoTypeAssociation, Database, Entry, Group, Value, TITLE_FIELD_NAME,
    USERNAME_FIELD_NAME, UUID_FIELD_NAME,
};

#[derive(Debug)]
enum Node {
    Entry(Entry),
    UUID(String),
    Group(Group),
    KeyValue(String, Value),
    AutoType(AutoType),
    AutoTypeAssociation(AutoTypeAssociation),
    ExpiryTime(String),
    Expires(bool),
    Tags(String),
}

pub const TAGS_SEPARATION_CHAR: &str = ";";

fn parse_xml_timestamp(t: &str) -> Result<chrono::NaiveDateTime> {
    match chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%SZ") {
        // Prior to KDBX4 file format, timestamps were stored as ISO 8601 strings
        Ok(ndt) => Ok(ndt),
        // In KDBX4, timestamps are stored as seconds, Base64 encoded, since 0001-01-01 00:00:00
        // So, if we don't have a valid ISO 8601 string, assume we have found a Base64 encoded int.
        _ => {
            let v = base64::decode(t).map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?;
            // Cast the Vec created by base64::decode into the array expected by i64::from_le_bytes
            let mut a: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
            a.copy_from_slice(&v[0..8]);
            let ndt =
                chrono::NaiveDateTime::parse_from_str("0001-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")
                    .unwrap()
                    + chrono::Duration::seconds(i64::from_le_bytes(a));
            Ok(ndt)
        }
    }
}

pub(crate) fn dump_database(db: &Database, inner_cipher: &mut dyn Cipher) -> Result<Vec<u8>> {
    let mut data: Vec<u8> = vec![];
    let mut writer = EmitterConfig::new()
        .perform_indent(false)
        .create_writer(&mut data);

    writer.write::<WriterEvent>(WriterEvent::start_element("KeePassFile").into());

    writer.write::<WriterEvent>(WriterEvent::start_element("Meta").into());

    writer.write::<WriterEvent>(WriterEvent::start_element("Generator").into());
    writer.write::<WriterEvent>(WriterEvent::characters("keepass-rs").into());
    writer.write::<WriterEvent>(WriterEvent::end_element().into());

    // TODO DatabaseName
    // TODO DatabaseNameChanged
    // TODO DatabaseDescription
    // TODO DatabaseDescriptionChanged
    // TODO DefaultUserName
    // TODO DefaultUserNameChanged
    // TODO MaintenanceHistoryDays
    // TODO Color
    // TODO MasterKeyChanged
    // TODO MasterKeyChangeRec
    // TODO MasterKeyChangeForce
    // TODO MemoryProtection
    // TODO CustomIcons
    // TODO RecycleBinEnabled
    // TODO RecycleBinUUID
    // TODO RecycleBinChanged
    // TODO EntryTemplatesGroup
    // TODO EntryTemplatesGroupChanged
    // TODO LastSelectedGroup
    // TODO LastTopVisibleGroup
    // TODO HistoryMaxItems
    // TODO HistoryMaxSize
    // TODO SettingsChanged
    // TODO CustomData

    writer.write::<WriterEvent>(WriterEvent::end_element().into());

    writer.write::<WriterEvent>(WriterEvent::start_element("Root").into());

    dump_xml_group(&mut writer, &db.root, inner_cipher);

    writer.write::<WriterEvent>(WriterEvent::end_element().into());
    writer.write::<WriterEvent>(WriterEvent::end_element().into());
    Ok(data)
}

pub(crate) fn dump_xml_group<E: std::io::Write>(
    writer: &mut EventWriter<E>,
    group: &Group,
    inner_cipher: &mut dyn Cipher,
) {
    writer.write::<WriterEvent>(WriterEvent::start_element("Group").into());

    // TODO Notes
    // TODO IconId

    writer.write::<WriterEvent>(WriterEvent::start_element("Name").into());
    writer.write::<WriterEvent>(WriterEvent::characters(&group.name).into());
    writer.write::<WriterEvent>(WriterEvent::end_element().into());

    writer.write::<WriterEvent>(WriterEvent::start_element(UUID_FIELD_NAME).into());
    writer.write::<WriterEvent>(WriterEvent::characters(&group.uuid).into());
    writer.write::<WriterEvent>(WriterEvent::end_element().into());

    for child in &group.children {
        match child {
            crate::Node::Entry(e) => dump_xml_entry(writer, e, inner_cipher),
            crate::Node::Group(g) => dump_xml_group(writer, g, inner_cipher),
        }
    }
    writer.write::<WriterEvent>(WriterEvent::end_element().into());
}

pub(crate) fn dump_xml_entry<E: std::io::Write>(
    writer: &mut EventWriter<E>,
    entry: &Entry,
    inner_cipher: &mut dyn Cipher,
) {
    writer.write::<WriterEvent>(WriterEvent::start_element("Entry").into());

    // TODO Notes
    // TODO IconId
    // TODO Times
    // TODO AutoType
    // TODO History
    // TODO ForegroundColor
    // TODO BackgroundColor
    //
    writer.write::<WriterEvent>(WriterEvent::start_element(UUID_FIELD_NAME).into());
    writer.write::<WriterEvent>(WriterEvent::characters(&entry.uuid).into());
    writer.write::<WriterEvent>(WriterEvent::end_element().into());

    writer.write::<WriterEvent>(WriterEvent::start_element("Expires").into());
    if entry.expires {
        writer.write::<WriterEvent>(WriterEvent::characters("True").into());
    } else {
        writer.write::<WriterEvent>(WriterEvent::characters("False").into());
    }
    writer.write::<WriterEvent>(WriterEvent::end_element().into());

    writer.write::<WriterEvent>(WriterEvent::start_element("Tags").into());
    writer.write::<WriterEvent>(
        WriterEvent::characters(&entry.tags.join(TAGS_SEPARATION_CHAR)).into(),
    );
    writer.write::<WriterEvent>(WriterEvent::end_element().into());

    for field_name in entry.fields.keys() {
        let field_value: String = match entry.fields.get(field_name).unwrap() {
            Value::Bytes(b) => std::str::from_utf8(b).unwrap().to_string(),
            // Value::Protected(sec_str) => sec_str.to_string(),
            Value::Protected(sec_str) => continue,
            Value::Unprotected(s) => s.to_string(),
        };
        writer.write::<WriterEvent>(WriterEvent::start_element("String").into());

        writer.write::<WriterEvent>(WriterEvent::start_element("Key").into());
        writer.write::<WriterEvent>(WriterEvent::characters(&field_name).into());
        writer.write::<WriterEvent>(WriterEvent::end_element().into());

        writer.write::<WriterEvent>(WriterEvent::start_element("Value").into());
        writer.write::<WriterEvent>(WriterEvent::characters(&field_value).into());
        writer.write::<WriterEvent>(WriterEvent::end_element().into());

        writer.write::<WriterEvent>(WriterEvent::end_element().into());
    }

    writer.write::<WriterEvent>(WriterEvent::end_element().into());
}

pub(crate) fn parse_xml_block(xml: &[u8], inner_cipher: &mut dyn Cipher) -> Result<Group> {
    let parser = EventReader::new(xml);

    // Stack of parsed Node objects not yet associated with their parent
    let mut parsed_stack: Vec<Node> = vec![];

    // Stack of XML element names
    let mut xml_stack: Vec<String> = vec![];

    let mut root_group: Group = Default::default();

    for e in parser {
        match e.unwrap() {
            XmlEvent::StartElement {
                name: OwnedName { ref local_name, .. },
                ref attributes,
                ..
            } => {
                xml_stack.push(local_name.clone());

                match &local_name[..] {
                    "Group" => parsed_stack.push(Node::Group(Default::default())),
                    "Entry" => parsed_stack.push(Node::Entry(Default::default())),
                    "String" => parsed_stack.push(Node::KeyValue(
                        String::new(),
                        Value::Unprotected(String::new()),
                    )),
                    "Value" => {
                        // Are we encountering a protected value?
                        if attributes
                            .iter()
                            .find(|oa| oa.name.local_name == "Protected")
                            .map(|oa| &oa.value)
                            .map_or(false, |v| v.to_lowercase().parse::<bool>().unwrap_or(false))
                        {
                            // Transform value to a Value::Protected
                            if let Some(&mut Node::KeyValue(_, ref mut ev)) =
                                parsed_stack.last_mut()
                            {
                                *ev = Value::Protected(SecStr::new(vec![]));
                            }
                        }
                    }
                    "AutoType" => parsed_stack.push(Node::AutoType(Default::default())),
                    "Association" => {
                        parsed_stack.push(Node::AutoTypeAssociation(Default::default()))
                    }
                    "ExpiryTime" => parsed_stack.push(Node::ExpiryTime(String::new())),
                    "Expires" => parsed_stack.push(Node::Expires(bool::default())),
                    "UUID" => parsed_stack.push(Node::UUID(Default::default())),
                    "Tags" => parsed_stack.push(Node::Tags(Default::default())),
                    _ => {}
                }
            }

            XmlEvent::EndElement {
                name: OwnedName { ref local_name, .. },
            } => {
                xml_stack.pop();

                if [
                    "Group",
                    "Entry",
                    "String",
                    "AutoType",
                    "Association",
                    "ExpiryTime",
                    "Expires",
                    "UUID",
                    "Tags",
                ]
                .contains(&&local_name[..])
                {
                    let finished_node = parsed_stack.pop().unwrap();
                    let parsed_stack_head = parsed_stack.last_mut();

                    match finished_node {
                        Node::KeyValue(k, v) => {
                            if let Some(&mut Node::Entry(Entry { ref mut fields, .. })) =
                                parsed_stack_head
                            {
                                // A KeyValue was finished inside of an Entry -> add a field
                                fields.insert(k, v);
                            }
                        }

                        Node::Group(finished_group) => {
                            match parsed_stack_head {
                                Some(&mut Node::Group(Group {
                                    ref mut children, ..
                                })) => {
                                    // A Group was finished - add Group to children
                                    children.push(crate::Node::Group(finished_group));
                                }
                                None => {
                                    // There is no more parent nodes left -> we are at the root
                                    root_group = finished_group;
                                }
                                _ => {}
                            }
                        }

                        Node::Entry(finished_entry) => {
                            if let Some(&mut Node::Group(Group {
                                ref mut children, ..
                            })) = parsed_stack_head
                            {
                                // A Entry was finished - add Node to parent Group's children
                                children.push(crate::Node::Entry(finished_entry))
                            }
                        }

                        Node::AutoType(at) => {
                            if let Some(&mut Node::Entry(Entry {
                                ref mut autotype, ..
                            })) = parsed_stack_head
                            {
                                autotype.replace(at);
                            }
                        }

                        Node::AutoTypeAssociation(ata) => {
                            if let Some(&mut Node::AutoType(AutoType {
                                ref mut associations,
                                ..
                            })) = parsed_stack_head
                            {
                                associations.push(ata);
                            }
                        }

                        Node::ExpiryTime(et) => {
                            // Currently ingoring any Err() from parse_xml_timestamp()
                            // Ignoring Err() to avoid possible regressions for existing users
                            if let Some(&mut Node::Entry(Entry { ref mut times, .. })) =
                                parsed_stack_head
                            {
                                match parse_xml_timestamp(&et) {
                                    Ok(t) => times.insert("ExpiryTime".to_owned(), t),
                                    _ => None,
                                };
                            } else if let Some(&mut Node::Group(Group { ref mut times, .. })) =
                                parsed_stack_head
                            {
                                match parse_xml_timestamp(&et) {
                                    Ok(t) => times.insert("ExpiryTime".to_owned(), t),
                                    _ => None,
                                };
                            }
                        }

                        Node::Expires(es) => {
                            if let Some(&mut Node::Entry(Entry {
                                ref mut expires, ..
                            })) = parsed_stack_head
                            {
                                *expires = es;
                            } else if let Some(&mut Node::Group(Group {
                                ref mut expires, ..
                            })) = parsed_stack_head
                            {
                                *expires = es;
                            }
                        }

                        Node::UUID(u) => {
                            if let Some(&mut Node::Entry(Entry { ref mut uuid, .. })) =
                                parsed_stack_head
                            {
                                *uuid = u;
                            } else if let Some(&mut Node::Group(Group { ref mut uuid, .. })) =
                                parsed_stack_head
                            {
                                *uuid = u;
                            }
                        }

                        Node::Tags(t) => {
                            if let Some(&mut Node::Entry(Entry { ref mut tags, .. })) =
                                parsed_stack_head
                            {
                                *tags = t
                                    .split(TAGS_SEPARATION_CHAR)
                                    .map(|x| x.to_owned())
                                    .collect();
                            }
                        }
                    }
                }
            }

            XmlEvent::Characters(c) => {
                // Got some character data that need to be matched to a Node on the parsed_stack.

                match (xml_stack.last().map(|s| &s[..]), parsed_stack.last_mut()) {
                    (Some("Name"), Some(&mut Node::Group(Group { ref mut name, .. }))) => {
                        // Got a "Name" element with a Node::Group on the parsed_stack
                        // Update the Group's name
                        *name = c;
                    }
                    (Some("ExpiryTime"), Some(&mut Node::ExpiryTime(ref mut et))) => {
                        *et = c;
                    }
                    (Some("UUID"), Some(&mut Node::UUID(ref mut uuid))) => {
                        *uuid = c;
                    }
                    (Some("Expires"), Some(&mut Node::Expires(ref mut es))) => {
                        *es = c == "True";
                    }
                    (Some("Tags"), Some(&mut Node::Tags(ref mut tags))) => {
                        *tags = c;
                    }
                    (Some("Key"), Some(&mut Node::KeyValue(ref mut k, _))) => {
                        // Got a "Key" element with a Node::KeyValue on the parsed_stack
                        // Update the KeyValue's key
                        *k = c;
                    }
                    (Some("Value"), Some(&mut Node::KeyValue(_, ref mut ev))) => {
                        // Got a "Value" element with a Node::KeyValue on the parsed_stack
                        // Update the KeyValue's value

                        match *ev {
                            Value::Bytes(_) => {} // not possible
                            Value::Unprotected(ref mut v) => {
                                *v = c;
                            }
                            Value::Protected(ref mut v) => {
                                // Use the decryptor to decrypt the protected
                                // and base64-encoded value
                                //
                                let buf = base64::decode(&c)
                                    .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?;

                                let buf_decode = inner_cipher.decrypt(&buf)?;

                                let c_decode = std::str::from_utf8(&buf_decode)
                                    .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?;

                                *v = SecStr::from(c_decode);
                            }
                        }
                    }
                    (Some("Enabled"), Some(&mut Node::AutoType(ref mut at))) => {
                        at.enabled = c.parse().unwrap_or(false);
                    }
                    (Some("DefaultSequence"), Some(&mut Node::AutoType(ref mut at))) => {
                        at.sequence = Some(c.to_owned());
                    }
                    (Some("Window"), Some(&mut Node::AutoTypeAssociation(ref mut ata))) => {
                        ata.window = Some(c.to_owned());
                    }
                    (
                        Some("KeystrokeSequence"),
                        Some(&mut Node::AutoTypeAssociation(ref mut ata)),
                    ) => {
                        ata.sequence = Some(c.to_owned());
                    }
                    _ => {}
                }
            }

            _ => {}
        }
    }

    Ok(root_group)
}
