#[macro_use]
extern crate dump;
extern crate blake2_rfc;
extern crate rustc_serialize;

use blake2_rfc::blake2b::{Blake2b, blake2b};
use rustc_serialize::base64::{ToBase64, URL_SAFE};

fn main() {
	blake2_rfc::blake2b::selftest();

	let secret = b"my secret key";
	let mut hash = Blake2b::with_key(16, &secret[..]);
	let token = b"not secret token data blah asdf";
	hash.update(&token[..]);
	let out = hash.finalize();
	dump!(out.as_bytes());

	let b64 = out.as_bytes().to_base64(URL_SAFE);
	dump!(b64);
}
