use eddo::{gen_keypair, PrivateKey, PublicKey, Signature};
use rand::rngs::OsRng;
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::io::{BufRead, Write};
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
    /// An error that occurrs when a signature check fails
    FailedSignature,
    /// An error that happened while doing IO of some kind
    IO(io::Error),
    /// An error that happened while doing hex decoding
    HexError(hex::FromHexError),
}

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> Self {
        AppError::IO(err)
    }
}

impl From<hex::FromHexError> for AppError {
    fn from(err: hex::FromHexError) -> Self {
        AppError::HexError(err)
    }
}

/// The type of result produced our application
type AppResult<T> = Result<T, AppError>;

fn decode_prefixed_hex<const N: usize>(prefix: &str, input: &str) -> AppResult<[u8; N]> {
    let just_hex = input
        .strip_prefix(prefix)
        .ok_or(AppError::ParseError("incorrect prefix".into()))?;
    if just_hex.len() != 2 * N {
        return Err(AppError::ParseError("incorrect size".into()));
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(just_hex, &mut bytes)?;
    Ok(bytes)
}

const PUBLIC_KEY_PREFIX: &'static str = "エッドの公開鍵";

fn format_public_key(public: PublicKey) -> String {
    format!("{}{}", PUBLIC_KEY_PREFIX, hex::encode(public.bytes))
}

fn decode_public_key(input: &str) -> AppResult<PublicKey> {
    Ok(PublicKey {
        bytes: decode_prefixed_hex(PUBLIC_KEY_PREFIX, input)?,
    })
}

const PRIVATE_KEY_PREFIX: &'static str = "エッドの秘密鍵";

fn format_private_key(private: PrivateKey) -> String {
    format!("{}{}", PRIVATE_KEY_PREFIX, hex::encode(private.bytes))
}

fn decode_private_key(input: &str) -> AppResult<PrivateKey> {
    Ok(PrivateKey {
        bytes: decode_prefixed_hex(PRIVATE_KEY_PREFIX, input)?,
    })
}

const SIGNATURE_PREFIX: &'static str = "エッドの署名";

fn format_signature(signature: Signature) -> String {
    format!("{}{}", SIGNATURE_PREFIX, hex::encode(signature.bytes))
}

fn decode_signature(input: &str) -> AppResult<Signature> {
    Ok(Signature {
        bytes: decode_prefixed_hex(SIGNATURE_PREFIX, input)?,
    })
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

fn sign(key_path: &Path, in_path: &Path) -> AppResult<()> {
    let key_file = File::open(key_path)?;
    let key_reader = BufReader::new(key_file);
    let mut maybe_private = None;
    for maybe_line in key_reader.lines() {
        let line = maybe_line?;
        if line.starts_with("#") {
            continue;
        }
        maybe_private = Some(decode_private_key(&line)?);
        break;
    }
    let private = maybe_private.ok_or(AppError::ParseError("no private key in file".into()))?;
    let in_data = fs::read(in_path)?;
    let sig = private.sign(&in_data);
    println!("{}", format_signature(sig));
    Ok(())
}

fn verify(public: PublicKey, signature: Signature, in_path: &Path) -> AppResult<()> {
    let in_data = fs::read(in_path)?;
    if !public.verify(&in_data, signature) {
        return Err(AppError::FailedSignature);
    }
    println!("Ok!");
    Ok(())
}

fn main() -> AppResult<()> {
    let args = Args::from_args();
    match args {
        Args::Generate { out_file } => generate(&out_file),
        Args::Sign { key_file, in_file } => sign(&key_file, &&in_file),
        Args::Verify {
            public,
            signature,
            in_file,
        } => {
            let public_key = decode_public_key(&public)?;
            let decoded_signature = decode_signature(&signature)?;
            verify(public_key, decoded_signature, &in_file)
        }
    }
}
