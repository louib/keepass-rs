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
        kdf_setting: KdfSettings,
        root: Group,
    ) -> Database {
        let mut outer_iv: Vec<u8> = vec![];
        let mut outer_iv_size = outer_cipher_suite.get_nonce_size();
        for _ in 0..outer_iv_size {
            // FIXME obviously this is not random.
            outer_iv.push(4);
        }

        let mut inner_random_stream_key: Vec<u8> = vec![];
        let mut inner_random_stream_key_size = inner_cipher_suite.get_nonce_size();
        for _ in 0..inner_random_stream_key_size {
            // FIXME obviously this is not random.
            inner_random_stream_key.push(4);
        }

        let mut kdf: KdfSettings;
        match kdf_setting {
            KdfSettings::Aes { rounds, .. } => {
                // FIXME obviously this is ugly. We should be able to change
                // the seed in the first kdf object.
                let mut kdf_seed: Vec<u8> = vec![];
                let mut kdf_seed_size = kdf_setting.seed_size();
                for _ in 0..kdf_seed_size {
                    // FIXME obviously this is not random.
                    kdf_seed.push(4);
                }
                kdf = KdfSettings::Aes {
                    seed: kdf_seed,
                    rounds,
                };
            }
            KdfSettings::Argon2 { .. } => {
                kdf = KdfSettings::Argon2 {
                    salt: vec![],
                    iterations: 100,
                    memory: 100,
                    parallelism: 1,
                    version: argon2::Version::Version13,
                };
            }
        };

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
                outer_iv,
                kdf,
                body_start: 0,
            }),
            inner_header: InnerHeader::KDBX4(KDBX4InnerHeader {
                inner_random_stream: inner_cipher_suite,
                inner_random_stream_key,
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
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
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
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
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
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
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
    pub fn kdbx4_with_password_no_compression() {
        let mut db = create_database(
            OuterCipherSuite::Twofish,
            Compression::None,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
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
    pub fn kdbx4_with_password_salsa20() {
        let mut db = create_database(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::Salsa20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
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
