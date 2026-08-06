//! Base64 encoding (RFC 4648 sec.4), for the places a signature format
//! insists on it.
//!
//! `ASiC` manifests and `XAdES` carry digests and certificates as base64
//! inside XML, because XML cannot hold arbitrary octets. Encoding only:
//! nothing in this crate consumes base64 that it did not produce, and a
//! decoder invites input this module has no business accepting.

/// The standard alphabet (RFC 4648 sec.4). Not the URL-safe variant --
/// XML has no objection to `+` or `/`.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Input octets per encoded quantum.
const QUANTUM_IN: usize = 3;

/// Output characters per encoded quantum.
const QUANTUM_OUT: usize = 4;

/// Bits carried by one output character.
const BITS_PER_CHARACTER: usize = 6;

/// Mask selecting one output character's worth of bits.
const CHARACTER_MASK: usize = 0x3F;

/// Bits in an octet.
const BITS_PER_OCTET: usize = 8;

/// Encode `input` as base64 with the standard alphabet and padding.
#[must_use]
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(QUANTUM_IN) * QUANTUM_OUT);
    for chunk in input.chunks(QUANTUM_IN) {
        // Pack the chunk right-aligned into a 24-bit accumulator, so a
        // short final chunk simply leaves the low bits zero.
        let mut packed = 0_usize;
        for index in 0..QUANTUM_IN {
            packed <<= BITS_PER_OCTET;
            packed |= usize::from(chunk.get(index).copied().unwrap_or(0));
        }
        // Every chunk yields four characters; the ones with no input
        // behind them become padding below.
        for index in 0..QUANTUM_OUT {
            let shift = BITS_PER_CHARACTER * (QUANTUM_OUT - 1 - index);
            let sextet = (packed >> shift) & CHARACTER_MASK;
            // `index <= chunk.len()` is the count of characters carrying
            // real input: one more than the octets supplied.
            if index <= chunk.len() {
                out.push(char::from(ALPHABET[sextet]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::encode;

    #[test]
    fn matches_rfc_4648_vectors() {
        // RFC 4648 sec.10, verbatim.
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn encodes_every_octet_value() {
        // All 256 values, so a sign-extension or alphabet-index slip
        // cannot hide in the range nothing else exercises.
        let all: Vec<u8> = (0..=u8::MAX).collect();
        let encoded = encode(&all);
        assert_eq!(encoded.len(), 344);
        assert!(encoded.starts_with("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"));
        assert!(encoded.ends_with("+/w=="));
    }
}
