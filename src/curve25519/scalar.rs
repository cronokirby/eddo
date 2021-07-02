use std::convert::TryInto;

use super::arithmetic::U256;

/// Represents a scalar in Z/(L) the order of our curve group.
///
/// The operations in this ring are defined through arithmetic modulo
/// L := 2^252 + 27742317777372353535851937790883648493
#[derive(Clone, Copy, Debug)]
// Only implement equality for tests. This is to avoid the temptation to introduce
// a timing leak through equality comparison in other situations.
#[cfg_attr(test, derive(PartialEq))]
pub struct Scalar {
    pub value: U256,
}

impl Scalar {
    /// Creates a new scalar from 32 bytes.
    ///
    /// This will apply a standard clamping procedure to the bytes, as described
    /// in Section 5.1.5:
    /// https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5
    pub fn clamped(mut bytes: [u8; 32]) -> Scalar {
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        let mut value = U256::from(0);
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            value.limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        Scalar { value }
    }
}
