extern crate hex;
extern crate subtle;

mod arch;
mod curve25519;
mod sha512;

pub use curve25519::{gen_keypair, PrivateKey, PublicKey, Signature};
