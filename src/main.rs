#[macro_use]
extern crate dump;
extern crate blake2_rfc;
extern crate rustc_serialize;

use blake2_rfc::blake2b::{Blake2b, blake2b};
use rustc_serialize::base64::{ToBase64, FromBase64, URL_SAFE};

// Enough for a 128-bit security level
const TOKEN_LENGTH: usize = 16;

/// Takes a secret key and message, and returns a signed token containing
/// (authenticator + message) that cannot be forged or verified without the
/// secret key.  The signed token is encoded with url-safe base64 and
/// contains the message in unencrypted format.
fn make_signed_token(key: &[u8], msg: &[u8]) -> String {
	let mut hash = Blake2b::with_key(TOKEN_LENGTH, key);
	hash.update(msg);
	let result = hash.finalize();
	let bytes = result.as_bytes();
	let token = [bytes, msg].concat();
	let token_b64 = token.to_base64(URL_SAFE);
	token_b64.to_owned()
}

/// TODO: make sure we don't have a timing attack

fn main() {
	blake2_rfc::blake2b::selftest();

	let payload = "not secret token data blah asdf".as_bytes();

	let secret = b"my secret key";
	let token = make_signed_token(&secret[..], payload);
	dump!(token);

	//let dec = b64.from_base64();

}
