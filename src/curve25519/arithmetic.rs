use std::ops::{Add, AddAssign};

use crate::arch::adc;

/// Represents a 256 bit unsigned integer.
///
/// This is intended to hold common behavior between the different modular arithmetic
/// behavior we need for our crate.
#[derive(Clone, Copy, Debug)]
// Only implement equality for tests. This is to avoid the temptation to introduce
// a timing leak through equality comparison in other situations.
#[cfg_attr(test, derive(PartialEq))]
pub struct U256 {
    limbs: [u64; 4],
}

impl AddAssign for U256 {
    fn add_assign(&mut self, other: U256) {
        let mut carry: u8 = 0;
        // Let's have confidence in Rust's ability to unroll this loop.
        for i in 0..4 {
            // Each intermediate result may generate up to 65 bits of output.
            // We need to daisy-chain the carries together, to get the right result.
            carry = adc(carry, self.limbs[i], other.limbs[i], &mut self.limbs[i]);
        }
    }
}

impl Add for U256 {
    type Output = Self;

    fn add(mut self, other: U256) -> Self::Output {
        self += other;
        self
    }
}

#[cfg(test)]
mod test {
    use super::U256;

    use proptest::prelude::*;

    prop_compose! {
        fn arb_u256()(
            z0 in any::<u64>(),
            z1 in any::<u64>(),
            z2 in any::<u64>(),
            z3 in any::<u64>()) -> U256 {
            U256 {
                limbs: [z0, z1, z2, z3]
            }
        }
    }

    proptest! {
        #[test]
        fn test_addition_commutative(a in arb_u256(), b in arb_u256()) {
            assert_eq!(a + b, b + a);
        }
    }
}
