use eddo::{gen_keypair, PrivateKey, PublicKey};
use rand::rngs::OsRng;
extern crate hex;

const PUBLIC_KEY_PREFIX: &'static str = "エッドの公開鍵";

fn format_public_key(public: PublicKey) -> String {
    format!("{}{}", PUBLIC_KEY_PREFIX, hex::encode(public.bytes))
}

const PRIVATE_KEY_PREFIX: &'static str = "エッドの秘密鍵";

fn format_private_key(private: PrivateKey) -> String {
    format!("{}{}", PRIVATE_KEY_PREFIX, hex::encode(private.bytes))
}

fn main() {
    let (public, private) = gen_keypair(&mut OsRng);
    println!("{}", format_public_key(public));
    println!("{}", format_private_key(private));
}
