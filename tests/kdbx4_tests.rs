mod kdbx4_tests {
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
        let mut root_group = Group::new("Root");
        root_group.children.push(Node::Entry(Entry::new()));
        let mut db = create_database(
            outer_cipher_suite,
            compression,
            inner_cipher_suite,
            kdf_setting,
            root_group,
            vec![],
        );

        // FIXME we should generate a random password here.
        let password = "test".to_string();
        let key_elements = key::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = dump(&db, &key_elements).unwrap();

        let decrypted_db = parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);
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
        let mut root_group = Group::new("Root");
        root_group.children.push(Node::Entry(Entry::new()));
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
