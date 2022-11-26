mod tests {
    use uuid::Uuid;

    use keepass::{
        config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
        db::{Database, Entry, Group, Header, InnerHeader, Node, KEEPASS_LATEST_ID},
        key,
        parse::kdbx4::*,
    };

    use std::collections::HashMap;
    use std::{fs::File, path::Path};

    fn create_database(
        outer_cipher_suite: OuterCipherSuite,
        compression: Compression,
        inner_cipher_suite: InnerCipherSuite,
        root: Group,
    ) -> Database {
        let mut nonce: Vec<u8> = vec![];
        let mut nonce_size = outer_cipher_suite.get_nonce_size();
        for _ in 0..nonce_size {
            // FIXME obviously this is not random.
            nonce.push(4);
        }

        Database {
            header: Header::KDBX4(KDBX4Header {
                version: KEEPASS_LATEST_ID,
                file_major_version: 4,
                file_minor_version: 3,
                outer_cipher: outer_cipher_suite,
                compression,
                master_seed: vec![
                    20, 101, 241, 68, 200, 91, 82, 118, 52, 156, 63, 110, 170, 88, 161, 210,
                ],
                outer_iv: nonce,
                kdf: KdfSettings::Aes {
                    seed: vec![
                        120, 166, 99, 138, 179, 29, 86, 23, 180, 75, 185, 223, 222, 163, 9, 102, 6,
                        230, 111, 31, 252, 134, 52, 71, 120, 190, 55, 3, 73, 249, 252, 99,
                    ],
                    rounds: 100,
                },
                body_start: 0,
            }),
            inner_header: InnerHeader::KDBX4(KDBX4InnerHeader {
                inner_random_stream: inner_cipher_suite,
                inner_random_stream_key: vec![
                    20, 100, 241, 67, 200, 91, 82, 118, 52, 156, 63, 110, 170, 88, 161, 210,
                ],
                binaries: vec![],
                body_start: 0,
            }),
            root,
        }
    }

    #[test]
    pub fn kdbx4_with_password_kdf_argon2_cipher_aes() {
        let mut db = create_database(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            Group {
                children: vec![Node::Entry(Entry {
                    uuid: Uuid::new_v4().to_string(),
                    fields: HashMap::default(),
                    times: HashMap::default(),
                    expires: false,
                    autotype: None,
                    tags: vec![],
                })],
                name: "Root".to_string(),
                uuid: Uuid::new_v4().to_string(),
                times: HashMap::default(),
                expires: false,
            },
        );

        let password = "test".to_string();
        let key_elements = key::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = dump(&db, &key_elements).unwrap();

        let decrypted_db = parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);
    }

    #[test]
    pub fn kdbx4_with_password_kdf_argon2_cipher_chacha() {
        let mut db = create_database(
            OuterCipherSuite::ChaCha20,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            Group {
                children: vec![Node::Entry(Entry {
                    uuid: Uuid::new_v4().to_string(),
                    fields: HashMap::default(),
                    times: HashMap::default(),
                    expires: false,
                    autotype: None,
                    tags: vec![],
                })],
                name: "Root".to_string(),
                uuid: Uuid::new_v4().to_string(),
                times: HashMap::default(),
                expires: false,
            },
        );

        let password = "test".to_string();
        let key_elements = key::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = dump(&db, &key_elements).unwrap();

        let decrypted_db = parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);
    }

    #[test]
    pub fn kdbx4_with_password_kdf_argon2_cipher_twofish() {
        let mut db = create_database(
            OuterCipherSuite::Twofish,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            Group {
                children: vec![Node::Entry(Entry {
                    uuid: Uuid::new_v4().to_string(),
                    fields: HashMap::default(),
                    times: HashMap::default(),
                    expires: false,
                    autotype: None,
                    tags: vec![],
                })],
                name: "Root".to_string(),
                uuid: Uuid::new_v4().to_string(),
                times: HashMap::default(),
                expires: false,
            },
        );

        let password = "test".to_string();
        let key_elements = key::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = dump(&db, &key_elements).unwrap();

        let decrypted_db = parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);
    }
}
