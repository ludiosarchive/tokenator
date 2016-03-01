#[macro_use]
extern crate dump;
extern crate blake2_rfc;
extern crate rustc_serialize;

use blake2_rfc::blake2b::Blake2b;
use rustc_serialize::base64::{ToBase64, FromBase64, URL_SAFE};

// We're OK with a 128-bit security level, but use 256 bits just in case.
const TOKEN_LENGTH: usize = 32;

/// Takes a secret key (up to 64 bytes in length) and a message (any length),
/// and returns a signed token containing (authenticator + message).
/// This token cannot be forged or verified without the secret key.
/// It is encoded with url-safe base64 and contains the message in unencrypted
/// format.
pub fn make_signed_token(key: &[u8], msg: &[u8]) -> String {
	let mut hash = Blake2b::with_key(TOKEN_LENGTH, key);
	hash.update(msg);
	let result = hash.finalize();
	let bytes = result.as_bytes();
	let token = [bytes, msg].concat();
	let token_b64 = token.to_base64(URL_SAFE);
	token_b64.to_owned()
}

pub fn check_signed_token(key: &[u8], token: &str) -> Result<(), String> {
	if token.len() < TOKEN_LENGTH {
		return Err(format!("token length {} < {}", token.len(), TOKEN_LENGTH));
	}
	Ok(())
}

/// Note: we don't encrypt the message because that would require us to never
/// reuse a nonce, which is a little tricky to get 100% right.  In the future,
/// we might want to use a SIV AES mode to do this:
/// https://eprint.iacr.org/2015/102.pdf
/// https://tools.ietf.org/html/rfc5297
/// "SIV provides a level of resistance to nonce reuse and misuse.  If the nonce is never reused, then the usual notion of nonce-based security of an authenticated encryption mode is achieved.  If, however, the nonce is reused, authenticity is retained and confidentiality is only compromised to the extent that an attacker can determine that the same plaintext (and same associated data) was protected with the same nonce and key"

// TODO: Use https://briansmith.org/rustdoc/ring/aead/index.html instead to
// encrypt tokens as well as a defense-in-depth measure

// TODO: make sure we don't have a timing attack

pub fn main() {
	blake2_rfc::blake2b::selftest();

	let payload = "not secret token data blah asdf".as_bytes();

	let secret = b"my secret key";
	let token = make_signed_token(&secret[..], payload);
	dump!(token);

	//let dec = b64.from_base64();

}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_make_signed_token() {
		let token = make_signed_token("my secret key".as_bytes(), "my message".as_bytes());
		assert_eq!(token, "aIQhyq5oVXY7ESI71JiIfyJ0_GKRRxRYsRM-trPdWgNteSBtZXNzYWdl");
	}
}
