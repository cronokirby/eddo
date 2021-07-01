extern crate hex;
extern crate subtle;

mod arch;
mod sha512;
mod curve25519;

pub fn hello() -> &'static str {
    "Hello World!"
}
