use std::error::Error;
use anyhow::{bail, Result};
use aead::{Aead, KeyInit, Payload};
use blake2::{Blake2b};
use hkdf::Hkdf;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::TryRngCore;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Generate an X25519 keypair (public, private)
pub fn create_x25519_keypair() -> (PublicKey, EphemeralSecret) {
    let private_key = EphemeralSecret::random();
    let public_key = PublicKey::from(&private_key);

    (public_key, private_key)
}

pub fn derive_key_hkdf(shared_secret: &[u8], info: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    // This IS equivalent to your Go code
    let hk = Hkdf::<Blake2b>::new(None, shared_secret);  // None = nil salt
    let mut key = [0u8; 32];
    hk.expand(info, &mut key)
        .map_err(|e| format!("failed to derive key: {}", e))?;
    Ok(key)
}

/// Encrypt with XChaCha20-Poly1305. Returns (ciphertext, nonce).
/// Uses a random 24-byte nonce (XNonce).
pub fn encrypt_xchacha20poly1305(plaintext: &[u8], key: &[u8]) -> Result<(Vec<u8>, [u8;24])> {
    if key.len() != 32 {
        bail!("key length must be 32");
    }
    let aead = XChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let mut nonce_bytes = [0u8; 24];
    OsRng::default().try_fill_bytes(&mut nonce_bytes)?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = aead
        .encrypt(nonce, Payload { msg: plaintext, aad: &[] })
        .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt with XChaCha20-Poly1305.
pub fn decrypt_xchacha20poly1305(ciphertext: &[u8], nonce_bytes: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        bail!("key length must be 32");
    }
    if nonce_bytes.len() != 24 {
        bail!("nonce length must be 24 for XChaCha20-Poly1305");
    }

    let aead = XChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = aead
        .decrypt(nonce, Payload { msg: ciphertext, aad: &[] })
        .map_err(|e| anyhow::anyhow!("decryption failed: {}", e))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_x25519_hkdf_xchacha() {
        // generate two keypairs
        let (pub_a, priv_a) = create_x25519_keypair();
        let (pub_b, priv_b) = create_x25519_keypair();

        let ss_a = priv_a.diffie_hellman(&pub_b);
        let ss_b = priv_b.diffie_hellman(&pub_a);

        assert_eq!(ss_a.to_bytes(), ss_b.to_bytes());

        let key_a = derive_key_hkdf(&ss_a.to_bytes(), b"test|uri").unwrap();
        let key_b = derive_key_hkdf(&ss_b.to_bytes(), b"test|uri").unwrap();
        assert_eq!(key_a, key_b);

        let plaintext = b"hello world";
        let (ct, nonce) = encrypt_xchacha20poly1305(plaintext, &key_a).unwrap();
        let pt = decrypt_xchacha20poly1305(&ct, &nonce, &key_b).unwrap();
        assert_eq!(pt, plaintext);
    }
}
