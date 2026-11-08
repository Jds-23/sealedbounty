//! Plain (non-`#[near]`) helpers for verifying NEAR AI Cloud TEE response signatures
//! and parsing the judge verdict. Reusable from any contract method.
//!
//! Signed text:
//! - provider_tee: `"{model}:{req_hex}:{resp_hex}"`
//! - gateway:      `"{req_hex}:{resp_hex}"`
//!
//! where `*_hex` = lowercase hex sha256 of the exact raw request / response bytes.

use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near, serde_json};

/// An allowlisted TEE signing identity.
///
/// JSON form is a tagged hex string:
/// - `"ed25519:<64 hex chars>"` (32-byte pubkey)
/// - `"eth:0x<40 hex chars>"`   (20-byte Ethereum address, any case)
#[near(serializers = [borsh, json])]
#[serde(into = "String", try_from = "String")]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Signer {
    Ed25519([u8; 32]),
    Eth([u8; 20]),
}

impl From<Signer> for String {
    fn from(s: Signer) -> String {
        match s {
            Signer::Ed25519(pk) => format!("ed25519:{}", hex::encode(pk)),
            Signer::Eth(a) => format!("eth:0x{}", hex::encode(a)),
        }
    }
}

impl TryFrom<String> for Signer {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        if let Some(h) = s.strip_prefix("ed25519:") {
            Ok(Signer::Ed25519(decode_hex_n::<32>(h)?))
        } else if let Some(h) = s.strip_prefix("eth:") {
            Ok(Signer::Eth(decode_hex_n::<20>(h)?))
        } else {
            Err("signer must be 'ed25519:<hex>' or 'eth:0x<hex>'".into())
        }
    }
}

/// Which signed-text format the signature covers.
#[near(serializers = [borsh, json])]
#[serde(rename_all = "snake_case")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigKind {
    ProviderTee,
    Gateway,
}

#[near(serializers = [borsh, json])]
#[serde(rename_all = "lowercase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// The judge's structured verdict, extracted from `choices[0].message.content`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub valid: bool,
    pub severity: Severity,
    #[serde(default)]
    pub cwe: Option<String>,
    pub confidence: u8,
}

// --- minimal OpenAI chat completion shape (unknown fields ignored) ---
#[derive(Deserialize, Serialize)]
#[serde(crate = "near_sdk::serde")]
struct ChatCompletion {
    choices: Vec<Choice>,
}
#[derive(Deserialize, Serialize)]
#[serde(crate = "near_sdk::serde")]
struct Choice {
    message: Message,
}
#[derive(Deserialize, Serialize)]
#[serde(crate = "near_sdk::serde")]
struct Message {
    content: Option<String>,
}

/// Decode exactly N bytes of hex, optional `0x` prefix, any case.
pub fn decode_hex_n<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).map_err(|_| format!("expected {N} bytes of hex"))?;
    Ok(out)
}

/// Lowercase hex sha256 of raw bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(env::sha256_array(bytes))
}

/// Normalise + validate a 32-byte hex hash (64 hex chars) to lowercase.
pub fn normalize_hash_hex(h: &str) -> Result<String, String> {
    let arr = decode_hex_n::<32>(h).map_err(|_| "req_hash must be 64 hex chars".to_string())?;
    Ok(hex::encode(arr))
}

/// The exact text the TEE signs.
pub fn signed_text(kind: SigKind, model: &str, req_hex: &str, resp_hex: &str) -> String {
    match kind {
        SigKind::ProviderTee => format!("{model}:{req_hex}:{resp_hex}"),
        SigKind::Gateway => format!("{req_hex}:{resp_hex}"),
    }
}

/// EIP-191 personal_sign digest: keccak256("\x19Ethereum Signed Message:\n" + len + text).
pub fn eip191_hash(text: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + text.len());
    buf.extend_from_slice(b"\x19Ethereum Signed Message:\n");
    buf.extend_from_slice(text.len().to_string().as_bytes());
    buf.extend_from_slice(text);
    env::keccak256_array(&buf)
}

pub fn verify_ed25519(pubkey: &[u8; 32], sig_hex: &str, text: &[u8]) -> bool {
    match decode_hex_n::<64>(sig_hex) {
        Ok(sig) => env::ed25519_verify(&sig, text, pubkey),
        Err(_) => false,
    }
}

/// Recover the Ethereum address that `personal_sign`ed `text`. `sig` = r||s||v, v in {27,28,0,1}.
pub fn recover_eth_address(sig_hex: &str, text: &[u8]) -> Option<[u8; 20]> {
    let sig = decode_hex_n::<65>(sig_hex).ok()?;
    let v = match sig[64] {
        27 | 28 => sig[64] - 27,
        0 | 1 => sig[64],
        _ => return None,
    };
    let hash = eip191_hash(text);
    // malleability_flag = true: reject high-s signatures.
    let pubkey = env::ecrecover(&hash, &sig[..64], v, true)?;
    let h = env::keccak256_array(pubkey);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..]);
    Some(addr)
}

pub fn verify_eth(addr: &[u8; 20], sig_hex: &str, text: &[u8]) -> bool {
    recover_eth_address(sig_hex, text).as_ref() == Some(addr)
}

pub fn verify_signature(signer: &Signer, sig_hex: &str, text: &[u8]) -> bool {
    match signer {
        Signer::Ed25519(pk) => verify_ed25519(pk, sig_hex, text),
        Signer::Eth(addr) => verify_eth(addr, sig_hex, text),
    }
}

/// Strip optional ```json / ``` fences around model output.
pub fn strip_fences(s: &str) -> &str {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("```") {
        // drop the info string line (e.g. "json")
        let rest = match rest.find('\n') {
            Some(i) => &rest[i + 1..],
            None => rest,
        };
        rest.trim_end().strip_suffix("```").unwrap_or(rest).trim()
    } else {
        t
    }
}

/// Parse an OpenAI chat completion body -> choices[0].message.content -> Verdict.
pub fn parse_verdict(resp_body: &[u8]) -> Result<Verdict, String> {
    let cc: ChatCompletion =
        serde_json::from_slice(resp_body).map_err(|e| format!("bad completion json: {e}"))?;
    let content = cc
        .choices
        .into_iter()
        .next()
        .and_then(|c| c.message.content)
        .ok_or("missing choices[0].message.content")?;
    let body = strip_fences(&content);
    match serde_json::from_str::<Verdict>(body) {
        Ok(v) => Ok(v),
        Err(e) => {
            // Fallback: outermost {...} if the model added prose around the JSON.
            match (body.find('{'), body.rfind('}')) {
                (Some(a), Some(b)) if a < b => serde_json::from_str::<Verdict>(&body[a..=b])
                    .map_err(|e| format!("bad verdict json: {e}")),
                _ => Err(format!("bad verdict json: {e}")),
            }
        }
    }
}

/// Full check: build the signed text from (model, req_hash, sha256(resp_body)) and verify.
pub fn verify_tee_signature(
    signer: &Signer,
    kind: SigKind,
    model: &str,
    req_hash: &str,
    resp_body: &[u8],
    sig_hex: &str,
) -> Result<(), String> {
    let req_hex = normalize_hash_hex(req_hash)?;
    let resp_hex = sha256_hex(resp_body);
    let text = signed_text(kind, model, &req_hex, &resp_hex);
    if verify_signature(signer, sig_hex, text.as_bytes()) {
        Ok(())
    } else {
        Err("bad signature".into())
    }
}
