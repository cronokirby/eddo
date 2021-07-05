use eddo::{gen_keypair, PrivateKey, PublicKey};
use rand::rngs::OsRng;
use std::io;
use std::io::Write;
use std::fs::File;
use std::path::{Path, PathBuf};
use structopt::StructOpt;

extern crate hex;
extern crate structopt;

#[derive(StructOpt, Debug)]
#[structopt(name = "eddo")]
enum Args {
    /// Generate a new keypair
    ///
    /// The public key will be printed out, the private key will be saved to a file
    Generate {
        /// The file to write the private key into
        #[structopt(short = "o", long = "out", parse(from_os_str))]
        out_file: PathBuf,
    },
    /// Verify a signature for a file, by a given public key
    Verify {
        /// The public key used to sign this file
        #[structopt(short = "p", long = "public")]
        public: String,
        /// The signature for this file
        #[structopt(short = "s", long = "signature")]
        signature: String,
        /// The file whose signature needs to be verified
        #[structopt(name = "INPUT_FILE", parse(from_os_str))]
        in_file: PathBuf,
    },
    /// Sign a file using your private key
    Sign {
        /// A path to your private key file
        #[structopt(short = "k", long = "key", parse(from_os_str))]
        key_file: PathBuf,
        /// The file contained the data to sign
        #[structopt(name = "INPUT_FILE", parse(from_os_str))]
        in_file: PathBuf,
    },
}

/// Represents the kind of error our application generates
#[derive(Debug)]
enum AppError {
    /// A parse error, with a string for information.
    ///
    /// This could probably be improved further.
    ParseError(String),
    /// An error that happened while doing IO of some kind
    IO(io::Error),
}

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> Self {
        AppError::IO(err)
    }
}

/// The type of result produced our application
type AppResult<T> = Result<T, AppError>;

const PUBLIC_KEY_PREFIX: &'static str = "エッドの公開鍵";

fn format_public_key(public: PublicKey) -> String {
    format!("{}{}", PUBLIC_KEY_PREFIX, hex::encode(public.bytes))
}

const PRIVATE_KEY_PREFIX: &'static str = "エッドの秘密鍵";

fn format_private_key(private: PrivateKey) -> String {
    format!("{}{}", PRIVATE_KEY_PREFIX, hex::encode(private.bytes))
}

fn generate(out_path: &Path) -> AppResult<()> {
    let (public, private) = gen_keypair(&mut OsRng);
    let formatted_public = format_public_key(public);
    let formatted_private = format_private_key(private);
    let mut out_file = File::create(out_path)?;
    writeln!(out_file, "# Public Key: {}", formatted_public)?;
    writeln!(out_file, "{}", formatted_private)?;
    Ok(())
}

fn main() -> AppResult<()> {
    let args = Args::from_args();
    match args {
        Args::Generate { out_file } => generate(&out_file),
        _ => unimplemented!(),
    }
}
