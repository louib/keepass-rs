mod kdbx4_tests {
    use uuid::Uuid;

    use keepass::{
        config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
        db::{Database, Entry, Group, Header, InnerHeader, Node, KEEPASS_LATEST_ID},
        key,
        parse::kdbx4::*,
    };

    use std::collections::HashMap;
    use std::{fs::File, path::Path};

    fn test_with_settings(
        outer_cipher_suite: OuterCipherSuite,
        compression: Compression,
        inner_cipher_suite: InnerCipherSuite,
        kdf_setting: KdfSettings,
    ) {
        let mut db = create_database(
            outer_cipher_suite,
            compression,
            inner_cipher_suite,
            kdf_setting,
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
            vec![],
        );

        let password = "test".to_string();
        let key_elements = key::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = dump(&db, &key_elements).unwrap();

        let decrypted_db = parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);
    }

    fn create_database(
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
        // FIXME this should work, but for some reason doesn't
        // getrandom::getrandom(&mut inner_random_stream_key);

        let mut kdf: KdfSettings;
        let mut kdf_seed: Vec<u8> = vec![];
        kdf_seed.resize(kdf_setting.seed_size().into(), 0);
        getrandom::getrandom(&mut kdf_seed);

        let mut master_seed: Vec<u8> = vec![];
        master_seed.resize(keepass::parse::kdbx4::HEADER_MASTER_SEED_SIZE.into(), 0);
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
                version: KEEPASS_LATEST_ID,
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
        }
    }

    #[test]
    pub fn aes256_chacha20_aes() {
        test_with_settings(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
        );
    }

    #[test]
    pub fn aes256_chacha20_argon2() {
        test_with_settings(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Argon2 {
                salt: vec![],
                iterations: 1000,
                memory: 134217728,
                parallelism: 8,
                version: argon2::Version::Version13,
            },
        );
    }

    #[test]
    pub fn aes256_salsa20_aes() {
        test_with_settings(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::Salsa20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
        );
    }

    #[test]
    pub fn aes256_salsa20_argon2() {
        test_with_settings(
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
        );
    }

    #[test]
    pub fn chacha20_chacha20_aes() {
        test_with_settings(
            OuterCipherSuite::ChaCha20,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
        );
    }

    #[test]
    pub fn chacha20_chacha20_aes_no_compression() {
        test_with_settings(
            OuterCipherSuite::ChaCha20,
            Compression::None,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
        );
    }

    #[test]
    pub fn chacha20_chacha20_argon2() {
        test_with_settings(
            OuterCipherSuite::ChaCha20,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Argon2 {
                salt: vec![],
                iterations: 1000,
                memory: 134217728,
                parallelism: 8,
                version: argon2::Version::Version13,
            },
        );
    }

    #[test]
    pub fn twofish_chacha20_aes() {
        test_with_settings(
            OuterCipherSuite::Twofish,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
        );
    }

    #[test]
    pub fn twofish_chacha20_aes_no_compression() {
        test_with_settings(
            OuterCipherSuite::Twofish,
            Compression::None,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
        );
    }

    #[test]
    pub fn twofish_chacha20_argon2() {
        test_with_settings(
            OuterCipherSuite::Twofish,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Argon2 {
                salt: vec![],
                iterations: 1000,
                memory: 134217728,
                parallelism: 8,
                version: argon2::Version::Version13,
            },
        );
    }

    #[test]
    pub fn binary_attachments() {
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
            vec![
                BinaryAttachment {
                    flags: 1,
                    content: vec![0x01, 0x02, 0x03, 0x04],
                },
                BinaryAttachment {
                    flags: 2,
                    content: vec![0x04, 0x03, 0x02, 0x01],
                },
            ],
        );

        let password = "test".to_string();
        let key_elements = key::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = dump(&db, &key_elements).unwrap();

        let decrypted_db = parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);

        let binaries = match decrypted_db.inner_header {
            keepass::InnerHeader::KDBX4(KDBX4InnerHeader {
                inner_random_stream,
                inner_random_stream_key,
                binaries,
            }) => binaries,
            _ => panic!(""),
        };
        assert_eq!(binaries.len(), 2);
        assert_eq!(binaries[0].flags, 1);
        assert_eq!(binaries[0].content, [0x01, 0x02, 0x03, 0x04]);
    }
}
