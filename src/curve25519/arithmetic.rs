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
