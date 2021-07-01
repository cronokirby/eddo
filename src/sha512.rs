//! This module exists to implement the SHA-512 hash function, which is necessary
//! for Ed25519 signatures.
//!
//! This file tries to follow RFC 6234 (https://datatracker.ietf.org/doc/html/rfc6234).

use std::{convert::TryInto, mem::size_of};

// This is the number of bytes in our 512 bit hash.
pub const HASH_SIZE: usize = 64;

/// BLOCK_SIZE is the number of bytes needed to make a 1024 bit block
///
/// This block structure is described in Section 4:
/// https://datatracker.ietf.org/doc/html/rfc6234#section-4
const BLOCK_SIZE: usize = 128;

// Utility functions, as in Section 5.2:
// https://datatracker.ietf.org/doc/html/rfc6234#section-5.2

#[inline]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
fn bsig0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[inline]
fn bsig1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[inline]
fn ssig0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

#[inline]
fn ssig1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// The table of constants used in SHA-512 (and SHA-384).
///
/// This table is at the end of Section 5.2:
/// https://datatracker.ietf.org/doc/html/rfc6234#section-5.2
#[rustfmt::skip]
const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// This is used to avoid allocating new space for the message schedule for each block.
///
/// This is a struct of our invention, and is used to carry out part 1 of the algorithm
/// in Section 6.3:
/// https://datatracker.ietf.org/doc/html/rfc6234#section-6.3
struct MessageSchedule {
    words: [u64; 80],
}

impl MessageSchedule {
    /// Create a new MessageSchedule
    ///
    /// This state shouldn't be used directly, but rather initialized with a message block.
    fn new() -> MessageSchedule {
        MessageSchedule { words: [0; 80] }
    }

    /// This prepares the message schedule with a new message block.
    ///
    /// This follows part 1 of the algorithm in Section 6.3:
    /// https://datatracker.ietf.org/doc/html/rfc6234#section-6.3
    fn prepare(&mut self, block: &[u8; BLOCK_SIZE]) {
        for (t, chunk) in block.chunks_exact(8).enumerate() {
            // Casting the chunk to the right size will never fail, because we use chunks_exact
            let mt = u64::from_be_bytes(chunk.try_into().unwrap());
            self.words[t] = mt;
        }
        for t in 16..=79 {
            self.words[t] = ssig1(self.words[t - 2])
                .wrapping_add(self.words[t - 7])
                .wrapping_add(ssig0(self.words[t - 15]))
                .wrapping_add(self.words[t - 16]);
        }
    }
}

/// Represents a "hash value", as described in Section 6:
/// https://datatracker.ietf.org/doc/html/rfc6234#section-6
///
/// This can be thought of as the ongoing state of our hash function,
/// which gets modified using our message blocks.
struct HashValue {
    data: [u64; 8],
    schedule: MessageSchedule,
}

impl HashValue {
    /// Create an initial hash value, as per Section 6.3:
    /// https://datatracker.ietf.org/doc/html/rfc6234#section-6.3
    fn initial() -> HashValue {
        HashValue {
            data: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            schedule: MessageSchedule::new(),
        }
    }

    /// Update the current hash value, as per Section 6.3:
    /// https://datatracker.ietf.org/doc/html/rfc6234#section-6.3
    fn update(&mut self, block: &[u8; BLOCK_SIZE]) {
        // The following titles are quoted from the algorithm in Section 6.3:

        // 1. Prepare the message schedule W:
        self.schedule.prepare(block);
        let w = self.schedule.words;

        // 2. Initialize the working variables:
        let mut a = self.data[0];
        let mut b = self.data[1];
        let mut c = self.data[2];
        let mut d = self.data[3];
        let mut e = self.data[4];
        let mut f = self.data[5];
        let mut g = self.data[6];
        let mut h = self.data[7];

        // 3. Perform the main hash computation:
        for t in 0..=79 {
            let t1 = h
                .wrapping_add(bsig1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let t2 = bsig0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        // 4. Compute the intermediate hash value H(i)
        self.data[0] = a.wrapping_add(self.data[0]);
        self.data[1] = b.wrapping_add(self.data[1]);
        self.data[2] = c.wrapping_add(self.data[2]);
        self.data[3] = d.wrapping_add(self.data[3]);
        self.data[4] = e.wrapping_add(self.data[4]);
        self.data[5] = f.wrapping_add(self.data[5]);
        self.data[6] = g.wrapping_add(self.data[6]);
        self.data[7] = h.wrapping_add(self.data[7]);
    }

    // This calculates the final result from a hash value, as per the end of Section 6.4:
    // https://datatracker.ietf.org/doc/html/rfc6234#section-6.4
    fn result(&self) -> [u8; HASH_SIZE] {
        let mut out = [0; HASH_SIZE];
        for (i, chunk) in out.chunks_exact_mut(size_of::<u64>()).enumerate() {
            chunk.copy_from_slice(&self.data[i].to_be_bytes());
        }
        out
    }
}

/// This calculates the SHA-512 hash of some arbitrary input, producing 512 bits of output.
///
/// This implements the function as defined in RFC 6234:
/// https://datatracker.ietf.org/doc/html/rfc6234
pub fn hash(message: &[u8]) -> [u8; HASH_SIZE] {
    let mut hash_value = HashValue::initial();

    let mut blocks = message.chunks_exact(BLOCK_SIZE);
    for block in &mut blocks {
        hash_value.update(block.try_into().unwrap());
    }

    let remainder = blocks.remainder();
    let remainder_len = remainder.len();

    // Now, we need to handle padding, as per Section 4.2:
    // https://datatracker.ietf.org/doc/html/rfc6234#section-4.2

    // This buffer is used to contain whatever remaining blocks we feed into the hasher
    let mut scratch_block = [0; BLOCK_SIZE];
    scratch_block[..remainder_len].copy_from_slice(remainder);

    // a. "1" is appended
    scratch_block[remainder_len] = 0b1000_0000;

    // b. K "0"s are appended where K is the smallest, non-negative solution
    // to the equation
    //     ( L + 1 + K ) mod 1024 = 896

    // Here, the 1 we add includes the zero bits we've already added.
    let l_plus_1 = remainder_len + 1;
    let desired_size = BLOCK_SIZE - size_of::<u128>();
    // In this case, we have two extra blocks, one of which is already ready
    if l_plus_1 > desired_size {
        hash_value.update(&scratch_block);
        scratch_block.fill(0);
    }

    // c. Then append the 128-bit block that is L in binary representation.
    let l = 8 * (message.len() as u128);
    scratch_block[BLOCK_SIZE - size_of::<u128>()..].copy_from_slice(&l.to_be_bytes());

    hash_value.update(&scratch_block);

    hash_value.result()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vectors() {
        let mut expected = [0; HASH_SIZE];

        let mut actual = hash(b"abcde");
        hex::decode_to_slice(
        "878ae65a92e86cac011a570d4c30a7eaec442b85ce8eca0c2952b5e3cc0628c2e79d889ad4d5c7c626986d452dd86374b6ffaa7cd8b67665bef2289a5c70b0a1",
        &mut expected,
        ).unwrap();
        assert_eq!(actual, expected);

        actual = hash(b"abc");
        hex::decode_to_slice(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        &mut expected,
        ).unwrap();
        assert_eq!(actual, expected);

        actual = hash(b"");
        hex::decode_to_slice(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        &mut expected,
        ).unwrap();
        assert_eq!(actual, expected);
        // This tests the case where our message is already a full block
        actual = hash(b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
        hex::decode_to_slice(
        "92fd0a1e6218274d4ab9824bf2be236ef8bdc5bd5fead472e04850f01aabcdfa8ecccc8d690fd86ae2295886ff26b4602e8f8651d12434a3cef0b4aff8ca13b4",
        &mut expected,
        ).unwrap();
        assert_eq!(actual, expected);
        // This tests the case where we need to produce two padding blocks
        actual = hash(b"23456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
        hex::decode_to_slice(
        "c3d3bdc93db599c39d1647d31e939cd3bdfa9aef649ef85c4ce1e6e9a4ead4471203f6681e9dda2834688d876e95aa2452fe9263dbc72999d54b5a87ebe637fc",
        &mut expected,
        ).unwrap();
        assert_eq!(actual, expected);
    }
}
