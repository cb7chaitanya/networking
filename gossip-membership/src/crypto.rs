/// ChaCha20-Poly1305 message encryption with per-node authentication.
///
/// Every encrypted datagram has the following layout:
/// ```text
///  Bytes  0-11  : nonce        (96-bit, random per message)
///  Bytes 12-19  : sender_id    (u64, cleartext — bound as AAD)
///  Bytes 20+    : ciphertext   (encrypted message bytes + 16-byte Poly1305 tag)
/// ```
///
/// The sender's `node_id` is included as Additional Authenticated Data (AAD).
/// Because the Poly1305 tag covers the AAD, any modification of the cleartext
/// `sender_id` causes decryption to fail.  This provides per-node
/// authentication: the receiver can trust that the message originated from the
/// claimed sender (given the shared cluster key).
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SENDER_ID_LEN: usize = 8;
/// Total overhead added to each encrypted datagram.
pub const CRYPTO_OVERHEAD: usize = NONCE_LEN + SENDER_ID_LEN + TAG_LEN;

// ── Errors ────────────────────────────────────────────────────────────────────
#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    BufferTooShort,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::BufferTooShort => write!(f, "encrypted buffer too short"),
        }
    }
}

impl std::error::Error for CryptoError {}

// ── Key generation ────────────────────────────────────────────────────────────
/// Generate a cryptographically random 256-bit key.
pub fn generate_key() -> [u8; KEY_LEN] {
    let mut bytes = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Encode key bytes as a lowercase hex string (64 chars).
pub fn key_to_hex(key: &[u8; KEY_LEN]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a 64-char hex string into key bytes.
pub fn key_from_hex(hex: &str) -> Option<[u8; KEY_LEN]> {
    if hex.len() != KEY_LEN * 2 {
        return None;
    }
    let mut bytes = [0u8; KEY_LEN];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Some(bytes)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── ClusterKey ────────────────────────────────────────────────────────────────
/// Shared symmetric key for cluster message encryption and authentication.
pub struct ClusterKey {
    raw: [u8; KEY_LEN],
    cipher: ChaCha20Poly1305,
}

impl Clone for ClusterKey {
    fn clone(&self) -> Self {
        Self::from_bytes(self.raw)
    }
}

impl std::fmt::Debug for ClusterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterKey")
            .field("cipher", &"<redacted>")
            .finish()
    }
}

impl ClusterKey {
    /// Create from raw 256-bit key bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        let key = Key::from(bytes);
        Self {
            raw: bytes,
            cipher: ChaCha20Poly1305::new(&key),
        }
    }

    /// Generate a new random cluster key.
    pub fn generate() -> Self {
        Self::from_bytes(generate_key())
    }

    /// Return the raw key bytes.
    pub fn raw_bytes(&self) -> &[u8; KEY_LEN] {
        &self.raw
    }

    /// Encrypt `plaintext` with `sender_id` as AAD.
    ///
    /// Returns `[nonce (12)][sender_id (8)][ciphertext + tag (len + 16)]`.
    pub fn encrypt(&self, plaintext: &[u8], sender_id: u64) -> Result<Vec<u8>, CryptoError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let aad = sender_id.to_be_bytes();
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut out = Vec::with_capacity(NONCE_LEN + SENDER_ID_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&aad);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a datagram produced by [`encrypt`](Self::encrypt).
    ///
    /// Returns `(plaintext, sender_id)`.  The `sender_id` is authenticated
    /// via AAD — if it was tampered with, decryption fails.
    pub fn decrypt(&self, data: &[u8]) -> Result<(Vec<u8>, u64), CryptoError> {
        if data.len() < NONCE_LEN + SENDER_ID_LEN + TAG_LEN {
            return Err(CryptoError::BufferTooShort);
        }

        let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
        let sender_id_bytes: [u8; SENDER_ID_LEN] = data[NONCE_LEN..NONCE_LEN + SENDER_ID_LEN]
            .try_into()
            .unwrap();
        let sender_id = u64::from_be_bytes(sender_id_bytes);
        let ciphertext = &data[NONCE_LEN + SENDER_ID_LEN..];

        let plaintext = self
            .cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &sender_id_bytes,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok((plaintext, sender_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let key = ClusterKey::generate();
        let plaintext = b"hello gossip";
        let sender_id: u64 = 42;

        let encrypted = key.encrypt(plaintext, sender_id).unwrap();
        let (decrypted, got_id) = key.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_eq!(got_id, sender_id);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = ClusterKey::generate();
        let key2 = ClusterKey::generate();

        let encrypted = key1.encrypt(b"secret", 1).unwrap();
        assert!(key2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn tampered_sender_id_fails() {
        let key = ClusterKey::generate();
        let mut encrypted = key.encrypt(b"data", 100).unwrap();

        // Tamper with the cleartext sender_id (bytes 12..20).
        encrypted[12] ^= 0xFF;

        assert!(key.decrypt(&encrypted).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = ClusterKey::generate();
        let mut encrypted = key.encrypt(b"data", 1).unwrap();

        // Tamper with the ciphertext body.
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;

        assert!(key.decrypt(&encrypted).is_err());
    }

    #[test]
    fn buffer_too_short_fails() {
        let key = ClusterKey::generate();
        assert!(key.decrypt(&[0u8; 10]).is_err());
    }

    #[test]
    fn different_nonces_each_call() {
        let key = ClusterKey::generate();
        let e1 = key.encrypt(b"same", 1).unwrap();
        let e2 = key.encrypt(b"same", 1).unwrap();

        // Nonces (first 12 bytes) must differ.
        assert_ne!(&e1[..12], &e2[..12]);
        // Ciphertext must also differ (due to different nonces).
        assert_ne!(e1, e2);
    }

    #[test]
    fn hex_roundtrip() {
        let raw = generate_key();
        let hex = key_to_hex(&raw);
        assert_eq!(hex.len(), 64);
        let back = key_from_hex(&hex).unwrap();
        assert_eq!(raw, back);
    }

    #[test]
    fn hex_case_insensitive() {
        let raw = generate_key();
        let upper = key_to_hex(&raw).to_uppercase();
        let back = key_from_hex(&upper).unwrap();
        assert_eq!(raw, back);
    }

    #[test]
    fn hex_bad_length_returns_none() {
        assert!(key_from_hex("abcd").is_none());
    }

    #[test]
    fn hex_bad_chars_returns_none() {
        let bad = "zz".to_string() + &"00".repeat(31);
        assert!(key_from_hex(&bad).is_none());
    }

    #[test]
    fn clone_key_can_decrypt() {
        let key = ClusterKey::generate();
        let encrypted = key.encrypt(b"test", 7).unwrap();
        let key2 = key.clone();
        let (plain, id) = key2.decrypt(&encrypted).unwrap();
        assert_eq!(plain, b"test");
        assert_eq!(id, 7);
    }
}
