#[macro_use]
extern crate dump;
extern crate blake2_rfc;
extern crate rustc_serialize;
extern crate constant_time_eq;

use blake2_rfc::blake2b::Blake2b;
use rustc_serialize::base64::{ToBase64, FromBase64, URL_SAFE};

// We're OK with a 128-bit security level, but use 256 bits just in case.
const TOKEN_LENGTH: usize = 32;

fn get_hash(key: &[u8], msg: &[u8]) -> Vec<u8> {
	let mut hash = Blake2b::with_key(TOKEN_LENGTH, key);
	hash.update(msg);
	let result = hash.finalize();
	result.as_bytes().to_vec()
}

/// Takes a secret key (up to 64 bytes in length) and a message (any length),
/// and returns a signed token containing (authenticator + message).
/// This token cannot be forged or verified without the secret key.
/// It is encoded with url-safe base64 and contains the message in unencrypted
/// format.
pub fn make_signed_token(key: &[u8], msg: &[u8]) -> String {
	let bytes = get_hash(key, msg);
	let token = [bytes.as_slice(), msg].concat();
	let token_b64 = token.to_base64(URL_SAFE);
	token_b64.to_owned()
}

/// Extract the message from a signed token, and only if it has the correct hash
pub fn get_signed_message(key: &[u8], token_b64: &str) -> Result<Vec<u8>, String> {
	let token = token_b64.from_base64();
	if token.is_err() {
		return Err(format!("token {:?} is invalid base64", token_b64));
	}
	let token = token.unwrap();
	if token.len() < TOKEN_LENGTH {
		return Err(format!("token length {} < {}", token.len(), TOKEN_LENGTH));
	}
	let given_hash = &token[0..TOKEN_LENGTH];
	let msg = &token[TOKEN_LENGTH..];
	let actual_hash = get_hash(key, msg);
	if !constant_time_eq::constant_time_eq(given_hash, actual_hash.as_slice()) {
		return Err(format!("token {:?} has wrong hash", token_b64));
	}
	Ok(msg.to_vec())
}

// TODO: embed expiration into signed message outside the JSON layer?

/// Note: we don't encrypt the message because that would require us to never
/// reuse a nonce, which is a little tricky to get 100% right.  In the future,
/// we might want to use a SIV AES mode to do this:
/// https://eprint.iacr.org/2015/102.pdf
/// https://tools.ietf.org/html/rfc5297
/// "SIV provides a level of resistance to nonce reuse and misuse.  If the nonce is never reused, then the usual notion of nonce-based security of an authenticated encryption mode is achieved.  If, however, the nonce is reused, authenticity is retained and confidentiality is only compromised to the extent that an attacker can determine that the same plaintext (and same associated data) was protected with the same nonce and key"

pub fn main() {
	blake2_rfc::blake2b::selftest();

	let message = "not secret token data blah asdf".as_bytes();

	let secret = b"my secret key";
	let token = make_signed_token(&secret[..], message);
	dump!(token);

	//let dec = b64.from_base64();

}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_make_check() {
		let key = b"my secret key";
		let message = b"my message";
		let token = make_signed_token(key, message);
		assert_eq!(token, "aIQhyq5oVXY7ESI71JiIfyJ0_GKRRxRYsRM-trPdWgNteSBtZXNzYWdl");
		let result = get_signed_message(key, &token[..]);
		assert_eq!(result, Ok(message.to_vec()));
	}
}
