mod xml_tests {
    use keepass::{
        config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
        db::{
            Database, DeletedObject, Entry, Group, Header, InnerHeader, Node,
            EXPIRY_TIME_FIELD_NAME, KEEPASS_LATEST_ID, PASSWORD_FIELD_NAME, ROOT_GROUP_NAME,
            TITLE_FIELD_NAME, USERNAME_FIELD_NAME,
        },
        key,
        parse::kdbx4::*,
    };
    use std::{convert::TryInto, str};

    use std::collections::HashMap;
    use std::{fs::File, path::Path};

    #[test]
    pub fn test_deleted_objects() {
        let deleted_entry_uuid = Entry::new().uuid.clone();
        let deleted_entry_deletion_time = 56565656;

        let mut db = create_database(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::Salsa20,
            KdfSettings::Argon2 {
                salt: vec![],
                iterations: 1000,
                memory: 1000,
                parallelism: 1,
                version: argon2::Version::Version13,
            },
            Group::new(ROOT_GROUP_NAME),
            vec![],
        );

        db.deleted_objects.push(DeletedObject {
            uuid: deleted_entry_uuid.clone(),
            deletion_time: chrono::NaiveDateTime::from_timestamp(deleted_entry_deletion_time, 0),
        });

        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::getrandom(&mut password_bytes);
        for random_char in password_bytes {
            password += &std::char::from_u32(random_char as u32).unwrap().to_string();
        }

        let key_elements = key::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = dump(&db, &key_elements).unwrap();

        let decrypted_db = parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 0);

        assert_eq!(decrypted_db.deleted_objects.len(), 1);
        assert_eq!(
            decrypted_db.deleted_objects[0].uuid.clone(),
            deleted_entry_uuid
        );
        assert_eq!(
            decrypted_db.deleted_objects[0].deletion_time.timestamp(),
            deleted_entry_deletion_time,
        );
    }

    #[test]
    pub fn test_entry() {
        let mut root_group = Group::new(ROOT_GROUP_NAME);
        let mut entry = Entry::new();
        let new_entry_uuid = entry.uuid.clone();
        let new_entry_expiry_timestamp = chrono::NaiveDateTime::from_timestamp(404420069755, 0);

        entry.fields.insert(
            TITLE_FIELD_NAME.to_string(),
            keepass::Value::Unprotected("ASDF".to_string()),
        );
        entry.fields.insert(
            USERNAME_FIELD_NAME.to_string(),
            keepass::Value::Unprotected("ghj".to_string()),
        );
        entry.fields.insert(
            PASSWORD_FIELD_NAME.to_string(),
            keepass::Value::Protected(str::from_utf8(b"klmno").unwrap().into()),
        );
        entry.tags.push("test".to_string());
        entry.tags.push("keepass-rs".to_string());
        entry.expires = true;
        entry.times.insert(
            EXPIRY_TIME_FIELD_NAME.to_string(),
            new_entry_expiry_timestamp,
        );

        root_group.children.push(Node::Entry(entry));

        let mut db = create_database(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::Salsa20,
            KdfSettings::Argon2 {
                salt: vec![],
                iterations: 1000,
                memory: 1000,
                parallelism: 1,
                version: argon2::Version::Version13,
            },
            root_group,
            vec![],
        );

        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::getrandom(&mut password_bytes);
        for random_char in password_bytes {
            password += &std::char::from_u32(random_char as u32).unwrap().to_string();
        }

        let key_elements = key::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = dump(&db, &key_elements).unwrap();

        let decrypted_db = parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);

        let decrypted_entry = match &decrypted_db.root.children[0] {
            Node::Entry(e) => e,
            Node::Group(g) => panic!("Was expecting an entry as the only child."),
        };

        assert_eq!(decrypted_entry.get_uuid(), new_entry_uuid);
        assert_eq!(decrypted_entry.get_title(), Some("ASDF"));
        assert_eq!(decrypted_entry.get_username(), Some("ghj"));
        assert_eq!(decrypted_entry.get(PASSWORD_FIELD_NAME), Some("klmno"));
        assert_eq!(
            decrypted_entry.tags,
            vec!["test".to_string(), "keepass-rs".to_string()]
        );

        assert_eq!(decrypted_entry.expires, true);
        if let Some(t) = decrypted_entry.get_expiry_time() {
            assert_eq!(t.timestamp(), new_entry_expiry_timestamp.timestamp());
        } else {
            panic!("Expected an ExpiryTime");
        }
    }

    #[test]
    pub fn test_group() {
        let mut root_group = Group::new(ROOT_GROUP_NAME);
        let mut entry = Entry::new();
        let new_entry_uuid = entry.uuid.clone();
        entry.fields.insert(
            TITLE_FIELD_NAME.to_string(),
            keepass::Value::Unprotected("ASDF".to_string()),
        );

        root_group.children.push(Node::Entry(entry));
        let root_group_notes = "This is a note related to the root group";
        root_group.notes = root_group_notes.to_string();

        let mut db = create_database(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::Salsa20,
            KdfSettings::Argon2 {
                salt: vec![],
                iterations: 1000,
                memory: 1000,
                parallelism: 1,
                version: argon2::Version::Version13,
            },
            root_group,
            vec![],
        );

        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::getrandom(&mut password_bytes);
        for random_char in password_bytes {
            password += &std::char::from_u32(random_char as u32).unwrap().to_string();
        }

        let key_elements = key::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = dump(&db, &key_elements).unwrap();

        let decrypted_db = parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);

        let decrypted_entry = match &decrypted_db.root.children[0] {
            Node::Entry(e) => e,
            Node::Group(g) => panic!("Was expecting an entry as the only child."),
        };

        assert_eq!(decrypted_entry.get_title(), Some("ASDF"));

        let decrypted_root_group = &decrypted_db.root;
        assert_eq!(decrypted_root_group.notes, root_group_notes);
        assert_eq!(decrypted_root_group.name, ROOT_GROUP_NAME);
    }
}
