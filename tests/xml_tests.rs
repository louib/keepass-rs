mod xml_tests {
    use keepass::{
        config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
        db::{
            Database, Entry, Group, Header, InnerHeader, Node, KEEPASS_LATEST_ID,
            USERNAME_FIELD_NAME,
        },
        key,
        parse::kdbx4::*,
    };
    use std::{convert::TryInto, str};

    use std::collections::HashMap;
    use std::{fs::File, path::Path};

    #[test]
    pub fn test_entry() {
        let mut root_group = Group::new("Root");
        let mut entry = Entry::new();
        let new_entry_uuid = entry.uuid.clone();
        entry.fields.insert(
            "Title".to_string(),
            keepass::Value::Unprotected("ASDF".to_string()),
        );
        entry.fields.insert(
            USERNAME_FIELD_NAME.to_string(),
            keepass::Value::Unprotected("ghj".to_string()),
        );
        entry.fields.insert(
            "Password".to_string(),
            keepass::Value::Protected(str::from_utf8(b"klmno").unwrap().into()),
        );
        entry.tags.push("test".to_string());
        entry.tags.push("keepass-rs".to_string());
        entry.expires = true;

        // Add an assertion that ExpiryTime.
        // assert_eq!(format!("{}", t), "2021-04-10 16:53:18");

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

        let password = "test".to_string();
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
        // assert_eq!(decrypted_entry.get_password(), Some("klmno"));
        assert_eq!(
            decrypted_entry.tags,
            vec!["test".to_string(), "keepass-rs".to_string()]
        );
        assert_eq!(decrypted_entry.expires, true);
        if let Some(t) = decrypted_entry.get_time("ExpiryTime") {
            // TODO enable that check
            // assert_eq!(format!("{}", t), "2021-04-10 16:53:18");
        } else {
            // panic!("Expected an ExpiryTime");
        }
    }
}
