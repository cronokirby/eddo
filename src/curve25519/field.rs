use subtle::{Choice, ConditionallySelectable};

use super::arithmetic::U256;

/// Represents an element in the field Z/(2^255 - 19).
///
/// The operations in this field are defined through arithmetic modulo
/// P := 2^255 - 19
///
/// # Creation
///
/// Elements in the field can be created from `u64`:
///
/// ```
/// let z = Z25519::from(48662);
/// ```
#[derive(Clone, Copy, Debug)]
// Only implement equality for tests. This is to avoid the temptation to introduce
// a timing leak through equality comparison in other situations.
#[cfg_attr(test, derive(PartialEq))]
struct Z25519 {
    value: U256,
}

impl From<u64> for Z25519 {
    fn from(x: u64) -> Self {
        Z25519 {
            value: U256::from(x),
        }
    }
}

impl ConditionallySelectable for Z25519 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Z25519 {
            value: U256::conditional_select(&a.value, &b.value, choice),
        }
    }
}
