//! Owner-encrypted report ciphertext (INTERFACE.md "Report ciphertext", v3 #2).
//!
//! `ciphertext = ephPub(32) || nonce(24) || nacl.box(body, nonce, ownerPub, ephSecret)`, i.e.
//! tweetnacl `box` = X25519 + HSalsa20 (crypto_box beforenm) + XSalsa20-Poly1305, with the
//! 16-byte Poly1305 tag in front of the encrypted body. RustCrypto `crypto_box::SalsaBox` is
//! byte-compatible (see the JS→Rust fixture test `tweetnacl_fixture_opens`).

use crypto_box::aead::Aead;
use crypto_box::{Nonce, PublicKey, SalsaBox, SecretKey};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = KEY_LEN + NONCE_LEN;

/// X25519 public key of `secret` (clamped, as tweetnacl `box.keyPair.fromSecretKey`).
pub fn x25519_base(secret: [u8; KEY_LEN]) -> [u8; KEY_LEN] {
    SecretKey::from(secret).public_key().to_bytes()
}

/// Open `ciphertext` with the hunter's ephemeral secret (the sender side of the box): requires
/// `x25519_base(eph_secret) == ciphertext[0..32]`, then opens the box for `owner_pub`.
pub fn open_with_ephemeral(
    ciphertext: &[u8],
    owner_pub: [u8; KEY_LEN],
    eph_secret: [u8; KEY_LEN],
) -> Result<Vec<u8>, &'static str> {
    if ciphertext.len() < HEADER_LEN + TAG_LEN {
        return Err("ciphertext too short");
    }
    if x25519_base(eph_secret) != ciphertext[..KEY_LEN] {
        return Err("ephemeral key mismatch");
    }
    let b = SalsaBox::new(&PublicKey::from(owner_pub), &SecretKey::from(eph_secret));
    let nonce: [u8; NONCE_LEN] = ciphertext[KEY_LEN..HEADER_LEN].try_into().unwrap();
    b.decrypt(&Nonce::from(nonce), &ciphertext[HEADER_LEN..])
        .map_err(|_| "box open failed")
}

/// Encrypt like shared/judge.mjs `encryptForOwner` with a chosen ephemeral secret and nonce.
pub fn seal_with_ephemeral(
    body: &[u8],
    owner_pub: [u8; KEY_LEN],
    eph_secret: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
) -> Vec<u8> {
    let b = SalsaBox::new(&PublicKey::from(owner_pub), &SecretKey::from(eph_secret));
    let boxed = b.encrypt(&Nonce::from(nonce), body).expect("encrypt");
    let mut out = Vec::with_capacity(HEADER_LEN + boxed.len());
    out.extend_from_slice(&x25519_base(eph_secret));
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&boxed);
    out
}
