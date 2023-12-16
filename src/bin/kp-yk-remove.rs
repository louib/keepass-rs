/// utility to remove a Yubikey from a database's key
use std::fs::File;

use anyhow::Result;
use clap::Parser;

use keepass::{ChallengeResponseKey, Database, DatabaseKey};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Provide a .kdbx database
    in_kdbx: String,

    /// Output file to write
    out_kdbx: String,

    /// The slot number of the yubikey to add to the Database
    yubikey_slot: String,

    /// Provide a keyfile
    #[arg(short = 'k', long)]
    keyfile: Option<String>,
}

pub fn main() -> Result<()> {
    let args = Args::parse();

    let mut source = File::open(args.in_kdbx)?;
    let mut key = DatabaseKey::new();

    if let Some(f) = args.keyfile {
        key = key.with_keyfile(&mut File::open(f)?)?;
    }

    key = key.with_password_from_prompt("Password (or blank for none): ")?;

    let key_without_yubikey = key.clone();

    key = key.with_challenge_response_key(ChallengeResponseKey::YubikeyChallenge(
        args.yubikey_slot,
        None,
    ));

    let db = Database::open(&mut source, key.clone())?;

    let mut out_file = File::create(args.out_kdbx)?;

    db.save(&mut out_file, key_without_yubikey)?;

    println!("Yubikey was removed from the database key.");

    Ok(())
}
