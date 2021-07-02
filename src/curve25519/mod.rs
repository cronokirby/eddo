use std::convert::TryInto;

use rand::{CryptoRng, Rng, RngCore};

use crate::{curve25519::scalar::Scalar, sha512};

mod arithmetic;
mod field;
mod point;
mod scalar;

const PUBLIC_KEY_SIZE: usize = 32;

pub struct PublicKey {
    pub bytes: [u8; PUBLIC_KEY_SIZE],
}

const PRIVATE_KEY_SIZE: usize = 32;

pub struct PrivateKey {
    pub bytes: [u8; PRIVATE_KEY_SIZE],
}

impl PrivateKey {
    fn derive_public_key(&self) -> PublicKey {
        let hash = sha512::hash(&self.bytes);
        let scalar = Scalar::clamped(hash[..32].try_into().unwrap());
        PublicKey {
            bytes: (&point::B * scalar).into(),
        }
    }
}

pub fn gen_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (PublicKey, PrivateKey) {
    let mut private = PrivateKey { bytes: [0u8; 32] };
    rng.fill_bytes(&mut private.bytes);
    (private.derive_public_key(), private)
}
