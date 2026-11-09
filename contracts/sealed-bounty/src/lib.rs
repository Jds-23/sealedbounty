//! SealedBounty escrow: bug-bounty programs paid out on NEAR AI Cloud TEE-signed judge verdicts.
//! Spec: docs/INTERFACE.md (binding).

pub mod tee;

use near_sdk::json_types::{Base64VecU8, U64, U128};
use near_sdk::serde::Deserialize;
use near_sdk::serde_json::{self, json};
use near_sdk::store::{IterableMap, LookupMap, LookupSet, Vector};
use near_sdk::{
    AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault, Promise, PromiseError,
    PromiseOrValue, env, near, require,
};

use tee::Severity;
pub use tee::{SigKind, Signer, Verdict};

const NANOS_PER_SEC: u64 = 1_000_000_000;
const DEFAULT_LIMIT: u64 = 50;
/// Static gas for the `on_payout` callback (reads/writes one claim + one program).
const GAS_ON_PAYOUT: Gas = Gas::from_tgas(10);

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerMeta {
    pub kind: SigKind,
    /// Which model this key serves. v3 (#3): a program only snapshots signers whose model equals
    /// its `model_id`; `None` matches no program.
    pub model: Option<String>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payouts {
    pub low: U128,
    pub medium: U128,
    pub high: U128,
    pub critical: U128,
}

impl Payouts {
    fn for_severity(&self, s: Severity) -> u128 {
        match s {
            Severity::None => 0,
            Severity::Low => self.low.0,
            Severity::Medium => self.medium.0,
            Severity::High => self.high.0,
            Severity::Critical => self.critical.0,
        }
    }
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub id: u64,
    pub owner: AccountId,
    pub name: String,
    pub repo_url: String,
    pub commit: String,
    pub model_id: String,
    pub system_prompt_hash: String,
    /// sha256hex of the canonical code bundle (64 lowercase hex). v2.
    pub code_hash: String,
    /// sha256hex of the canonical JSON of the request params
    /// `{chat_template_kwargs, max_tokens, response_format, temperature}`. v3 (#1).
    pub params_hash: String,
    /// v3 (#3): signers accepted for this program, snapshotted from the global allowlist at
    /// creation (model-matched). Later `add_signer` calls don't affect it; the owner rotates it
    /// with `set_program_signers`.
    pub signers: Vec<Signer>,
    /// Hunter stake (yocto) attached on top of storage to `submit_claim`. v3 #4.
    pub bond: U128,
    pub payouts: Payouts,
    pub owner_enc_pubkey: String,
    pub dispute_secs: u64,
    pub min_confidence: u8,
    /// Unreserved pool.
    pub balance: U128,
    /// Sum of payouts of Pending claims.
    pub reserved: U128,
    pub open: bool,
    pub created_at: U64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimStatus {
    Pending,
    Rejected,
    Paid,
    /// The payout transfer failed (e.g. the hunter account was deleted); payout + bond went back
    /// to the program balance. v3 #8.
    PayoutFailed,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub id: u64,
    pub program_id: u64,
    pub hunter: AccountId,
    pub req_hash: String,
    pub resp_hash: String,
    pub verdict: Verdict,
    pub signer: Signer,
    pub kind: SigKind,
    pub signature: String,
    pub model: String,
    pub ciphertext: String,
    pub status: ClaimStatus,
    pub payout: U128,
    pub submitted_at: U64,
    pub finalize_after: U64,
    pub reject_reason: Option<String>,
    /// Hunter bond held by this claim: returned on Paid, forfeited to the pool on Rejected. v3 #4.
    pub bond: U128,
}

#[near]
#[derive(BorshStorageKey)]
enum StorageKey {
    Signers,
    Programs,
    Claims,
    UsedReqHashes,
    Revoked,
    ClaimsByProgram,
    ProgramClaims { program_id: u64 },
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner: AccountId,
    signers: IterableMap<Signer, SignerMeta>,
    programs: IterableMap<u64, Program>,
    claims: IterableMap<u64, Claim>,
    /// Per-program claim ids in submission order, so `list_claims` never scans other programs (#7).
    claims_by_program: LookupMap<u64, Vector<u64>>,
    /// Keys are `dedupe_key(program_id, req_hash)` = `"<program_id>:<req_hash>"`.
    used_req_hashes: LookupSet<String>,
    next_program_id: u64,
    next_claim_id: u64,
    /// v3 (#6): signers revoked by the admin; their pending claims are rejected at finalize.
    revoked: LookupSet<Signer>,
}

/// NEP-297 event: `EVENT_JSON:{"standard":"sealedbounty","version":"1.0.0","event":..,"data":[..]}`.
fn emit(event: &str, data: serde_json::Value) {
    env::log_str(&format!(
        "EVENT_JSON:{}",
        json!({"standard": "sealedbounty", "version": "1.0.0", "event": event, "data": [data]})
    ));
}

/// Storage cost of the bytes added since `before`. Panics if `attached` does not cover it.
fn charge_storage(before: u64, attached: NearToken) -> NearToken {
    let used = env::storage_usage().saturating_sub(before);
    let cost = env::storage_byte_cost().saturating_mul(used as u128);
    require!(attached >= cost, "insufficient storage deposit");
    cost
}

/// `used_req_hashes` key: duplicates are per program (v3 #5), so a judgement copied into another
/// program can't burn the hash for the real one.
pub(crate) fn dedupe_key(program_id: u64, req_hash: &str) -> String {
    format!("{program_id}:{req_hash}")
}

/// Lenient shape of the judge request (unknown fields ignored) for the prompt/model/code checks;
/// the exact shape is enforced by [`StrictRequest`] at the params step.
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct JudgeRequest {
    model: String,
    messages: Vec<JudgeMessage>,
}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct JudgeMessage {
    role: String,
    content: serde_json::Value,
}

/// Strict shape of the canonical judge request (v3 #1): exactly these top-level keys and exactly
/// `{role, content}` per message. Values are parsed with [`NoDupValue`], so no object anywhere may
/// repeat a key (a provider could read the first copy where we read the last).
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct StrictRequest {
    #[allow(dead_code)]
    model: NoDupValue,
    #[allow(dead_code)]
    messages: Vec<StrictMessage>,
    response_format: NoDupValue,
    chat_template_kwargs: NoDupValue,
    temperature: NoDupValue,
    max_tokens: NoDupValue,
}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct StrictMessage {
    #[allow(dead_code)]
    role: NoDupValue,
    #[allow(dead_code)]
    content: NoDupValue,
}

/// A `serde_json::Value` whose objects must not contain duplicate keys.
struct NoDupValue(serde_json::Value);

impl<'de> Deserialize<'de> for NoDupValue {
    fn deserialize<D: near_sdk::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use near_sdk::serde::de::{Error, MapAccess, SeqAccess, Visitor};
        use serde_json::Value;
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Value;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("JSON value")
            }
            fn visit_bool<E>(self, b: bool) -> Result<Value, E> {
                Ok(Value::Bool(b))
            }
            fn visit_i64<E>(self, n: i64) -> Result<Value, E> {
                Ok(n.into())
            }
            fn visit_u64<E>(self, n: u64) -> Result<Value, E> {
                Ok(n.into())
            }
            fn visit_f64<E>(self, n: f64) -> Result<Value, E> {
                Ok(n.into())
            }
            fn visit_str<E>(self, s: &str) -> Result<Value, E> {
                Ok(s.into())
            }
            fn visit_string<E>(self, s: String) -> Result<Value, E> {
                Ok(s.into())
            }
            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut v = Vec::new();
                while let Some(NoDupValue(x)) = seq.next_element()? {
                    v.push(x);
                }
                Ok(Value::Array(v))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut m = serde_json::Map::new();
                while let Some(k) = map.next_key::<String>()? {
                    if m.contains_key(&k) {
                        return Err(A::Error::custom(format!("duplicate key {k}")));
                    }
                    let NoDupValue(v) = map.next_value()?;
                    m.insert(k, v);
                }
                Ok(Value::Object(m))
            }
        }
        d.deserialize_any(V).map(NoDupValue)
    }
}

/// Canonical JSON (v3 #1): object keys sorted recursively (byte order), no whitespace, serde_json
/// escapes. Sorts explicitly: near-sdk enables serde_json `preserve_order`, so `Value` maps keep
/// insertion order and plain `to_string` would NOT be canonical.
pub(crate) fn canonical_json(v: &serde_json::Value) -> String {
    use serde_json::Value;
    fn write(v: &Value, out: &mut String) {
        match v {
            Value::Array(a) => {
                out.push('[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(x, out);
                }
                out.push(']');
            }
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&Value::String(k.clone()).to_string());
                    out.push(':');
                    write(&m[k], out);
                }
                out.push('}');
            }
            scalar => out.push_str(&scalar.to_string()),
        }
    }
    let mut out = String::new();
    write(v, &mut out);
    out
}

/// `Some(params_hash)` if `request_body` has exactly the canonical request shape (no unknown or
/// missing keys, no duplicate keys anywhere), else `None`.
/// params_hash = sha256hex(canonical_json({chat_template_kwargs, max_tokens, response_format, temperature})).
pub(crate) fn request_params_hash(request_body: &str) -> Option<String> {
    let r = serde_json::from_str::<StrictRequest>(request_body).ok()?;
    let params = json!({
        "chat_template_kwargs": r.chat_template_kwargs.0,
        "max_tokens": r.max_tokens.0,
        "response_format": r.response_format.0,
        "temperature": r.temperature.0,
    });
    Some(tee::sha256_hex(canonical_json(&params).as_bytes()))
}

pub(crate) const TAMPERED: &str = "system prompt tampered";
pub(crate) const MODEL_MISMATCH: &str = "model mismatch";
pub(crate) const PARAMS_TAMPERED: &str = "params tampered";
pub(crate) const CODE_MISMATCH: &str = "code mismatch";
pub(crate) const HUNTER_MISMATCH: &str = "hunter mismatch";
pub(crate) const REPORT_MISSING: &str = "report missing";
pub(crate) const SIGNER_REVOKED: &str = "signer revoked";

/// `None` if the revealed request matches the program and the claim's hunter, else the FIRST
/// failing reject reason (INTERFACE.md v3 order):
/// 1. system prompt tampered (also: not JSON, or more than 3 messages)
/// 2. model mismatch
/// 3. params tampered (not exactly the canonical keys, duplicate keys, or params hash != params_hash)
/// 4. code mismatch (messages[1] role/TARGET line/CODE framing/code hash)
/// 5. hunter mismatch (only the HUNTER line differs from `hunter`)
/// 6. report missing
fn tamper_reason(
    program: &Program,
    hunter: &AccountId,
    request_body: &str,
) -> Option<&'static str> {
    let Ok(req) = serde_json::from_str::<JudgeRequest>(request_body) else {
        return Some(TAMPERED);
    };
    let prompt_ok = req.messages.len() <= 3
        && match req.messages.first() {
            Some(m) if m.role == "system" => m
                .content
                .as_str()
                .is_some_and(|c| tee::sha256_hex(c.as_bytes()) == program.system_prompt_hash),
            _ => false,
        };
    if !prompt_ok {
        return Some(TAMPERED);
    }
    if req.model != program.model_id {
        return Some(MODEL_MISMATCH);
    }
    if request_params_hash(request_body).as_deref() != Some(program.params_hash.as_str()) {
        return Some(PARAMS_TAMPERED);
    }
    if let Err(r) = code_check(program, hunter, req.messages.get(1)) {
        return Some(r);
    }
    let report_ok = match req.messages.get(2) {
        Some(m) if m.role == "user" => m
            .content
            .as_str()
            .is_some_and(|c| c.starts_with("REPORT\n")),
        _ => false,
    };
    if !report_ok {
        return Some(REPORT_MISSING);
    }
    None
}

/// messages[1] must be exactly `TARGET <repo>@<commit>\nHUNTER <hunter>\n\nCODE\n<bundle>` with
/// sha256hex(bundle) == code_hash. The TARGET line is checked first, then the CODE framing and
/// hash; only if everything but the HUNTER line matches is it a hunter mismatch.
fn code_check(
    program: &Program,
    hunter: &AccountId,
    msg: Option<&JudgeMessage>,
) -> Result<(), &'static str> {
    let content = match msg {
        Some(m) if m.role == "user" => m.content.as_str().ok_or(CODE_MISMATCH)?,
        _ => return Err(CODE_MISMATCH),
    };
    let target = format!("TARGET {}@{}\n", program.repo_url, program.commit);
    let rest = content
        .strip_prefix(target.as_str())
        .and_then(|r| r.strip_prefix("HUNTER "))
        .ok_or(CODE_MISMATCH)?;
    let (claimed_hunter, rest) = rest.split_once('\n').ok_or(CODE_MISMATCH)?;
    let bundle = rest.strip_prefix("\nCODE\n").ok_or(CODE_MISMATCH)?;
    if tee::sha256_hex(bundle.as_bytes()) != program.code_hash {
        return Err(CODE_MISMATCH);
    }
    if claimed_hunter != hunter.as_str() {
        return Err(HUNTER_MISMATCH);
    }
    Ok(())
}

#[near]
impl Contract {
    #[init]
    pub fn new(owner: Option<AccountId>) -> Self {
        Self {
            owner: owner.unwrap_or_else(env::predecessor_account_id),
            signers: IterableMap::new(StorageKey::Signers),
            programs: IterableMap::new(StorageKey::Programs),
            claims: IterableMap::new(StorageKey::Claims),
            claims_by_program: LookupMap::new(StorageKey::ClaimsByProgram),
            used_req_hashes: LookupSet::new(StorageKey::UsedReqHashes),
            next_program_id: 0,
            next_claim_id: 0,
            revoked: LookupSet::new(StorageKey::Revoked),
        }
    }

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
    }

    fn program_mut(&mut self, id: u64) -> &mut Program {
        self.programs
            .get_mut(&id)
            .unwrap_or_else(|| env::panic_str("program not found"))
    }

    fn assert_program_owner(p: &Program) {
        require!(
            env::predecessor_account_id() == p.owner,
            "program owner only"
        );
    }

    // ---------------- admin: signer allowlist ----------------

    pub fn add_signer(&mut self, signer: Signer, meta: SignerMeta) {
        self.assert_owner();
        emit(
            "signer_added",
            json!({"signer": signer, "kind": meta.kind, "model": meta.model}),
        );
        self.signers.insert(signer, meta);
    }

    pub fn remove_signer(&mut self, signer: Signer) -> bool {
        self.assert_owner();
        let removed = self.signers.remove(&signer).is_some();
        if removed {
            emit("signer_removed", json!({"signer": signer}));
        }
        removed
    }

    /// v3 (#6): admin only. Removes `signer` from the allowlist AND marks it revoked: its pending
    /// claims are rejected at finalize ("signer revoked"). The admin can block payouts this way
    /// but can't redirect them. Returns true if it was newly revoked.
    pub fn revoke_signer(&mut self, signer: Signer) -> bool {
        self.assert_owner();
        self.signers.remove(&signer);
        let newly = self.revoked.insert(signer.clone());
        if newly {
            emit("signer_revoked", json!({"signer": signer}));
        }
        newly
    }

    pub fn is_signer_revoked(&self, signer: Signer) -> bool {
        self.revoked.contains(&signer)
    }

    /// `requested` None → every allowlisted signer whose `meta.model == model_id`. Some(list) →
    /// each entry must be allowlisted with that model ("signer not allowlisted"); duplicates are
    /// dropped. Panics "no signers for model" if the result is empty.
    fn program_signers(&self, model_id: &str, requested: Option<Vec<Signer>>) -> Vec<Signer> {
        let matches = |m: &SignerMeta| m.model.as_deref() == Some(model_id);
        let out: Vec<Signer> = match requested {
            None => self
                .signers
                .iter()
                .filter(|(_, m)| matches(m))
                .map(|(s, _)| s.clone())
                .collect(),
            Some(list) => {
                let mut out: Vec<Signer> = Vec::with_capacity(list.len());
                for s in list {
                    require!(
                        self.signers.get(&s).is_some_and(matches),
                        "signer not allowlisted"
                    );
                    if !out.contains(&s) {
                        out.push(s);
                    }
                }
                out
            }
        };
        require!(!out.is_empty(), "no signers for model");
        out
    }

    pub fn get_signers(&self) -> Vec<(Signer, SignerMeta)> {
        self.signers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    // ---------------- programs ----------------

    /// Payable. Attached deposit minus the storage cost of the new program becomes `balance`.
    #[payable]
    #[allow(clippy::too_many_arguments)]
    pub fn create_program(
        &mut self,
        name: String,
        repo_url: String,
        commit: String,
        model_id: String,
        system_prompt_hash: String,
        code_hash: String,
        params_hash: String,
        payouts: Payouts,
        owner_enc_pubkey: String,
        dispute_secs: u64,
        min_confidence: u8,
        bond: U128,
        signers: Option<Vec<Signer>>,
    ) -> u64 {
        let system_prompt_hash = tee::normalize_hash_hex(&system_prompt_hash)
            .unwrap_or_else(|_| env::panic_str("system_prompt_hash must be 64 hex chars"));
        let code_hash = tee::normalize_hash_hex(&code_hash)
            .unwrap_or_else(|_| env::panic_str("code_hash must be 64 hex chars"));
        let params_hash = tee::normalize_hash_hex(&params_hash)
            .unwrap_or_else(|_| env::panic_str("params_hash must be 64 hex chars"));
        require!(min_confidence <= 100, "min_confidence must be <= 100");
        require!(
            dispute_secs.checked_mul(NANOS_PER_SEC).is_some(),
            "dispute_secs too large"
        );
        let signers = self.program_signers(&model_id, signers);

        let before = env::storage_usage();
        let attached = env::attached_deposit();
        let id = self.next_program_id;
        self.next_program_id += 1;
        let owner = env::predecessor_account_id();
        self.programs.insert(
            id,
            Program {
                id,
                owner: owner.clone(),
                name,
                repo_url,
                commit,
                model_id: model_id.clone(),
                system_prompt_hash,
                code_hash,
                params_hash,
                signers,
                bond,
                payouts,
                owner_enc_pubkey,
                dispute_secs,
                min_confidence,
                balance: U128(0),
                reserved: U128(0),
                open: true,
                created_at: U64(env::block_timestamp()),
            },
        );
        self.programs.flush();
        let cost = charge_storage(before, attached);
        let balance = attached.saturating_sub(cost).as_yoctonear();
        // Fixed-size field: rewriting it does not change storage usage.
        self.program_mut(id).balance = U128(balance);
        emit(
            "program_created",
            json!({"program_id": id, "owner": owner, "model_id": model_id, "balance": U128(balance)}),
        );
        id
    }

    /// v3 (#3): program owner only. Replaces the program's signer set (e.g. after re-attesting
    /// with `sb attest`); same subset rule as `create_program`. Affects future submissions only.
    /// Payable for any storage growth; unused deposit is refunded.
    #[payable]
    pub fn set_program_signers(&mut self, program_id: u64, signers: Vec<Signer>) {
        let p = self
            .programs
            .get(&program_id)
            .unwrap_or_else(|| env::panic_str("program not found"));
        Self::assert_program_owner(p);
        let model_id = p.model_id.clone();
        let signers = self.program_signers(&model_id, Some(signers));
        let before = env::storage_usage();
        let attached = env::attached_deposit();
        self.program_mut(program_id).signers = signers.clone();
        self.programs.flush();
        let cost = charge_storage(before, attached);
        let refund = attached.saturating_sub(cost);
        if !refund.is_zero() {
            Promise::new(env::predecessor_account_id())
                .transfer(refund)
                .detach();
        }
        emit(
            "program_signers_set",
            json!({"program_id": program_id, "signers": signers}),
        );
    }

    /// Payable. Adds the attached deposit to the program's unreserved balance.
    #[payable]
    pub fn fund_program(&mut self, program_id: u64) {
        let amount = env::attached_deposit().as_yoctonear();
        require!(amount > 0, "attach a deposit");
        let p = self.program_mut(program_id);
        require!(p.open, "program closed");
        p.balance = U128(p.balance.0 + amount);
        let balance = p.balance;
        emit(
            "program_funded",
            json!({"program_id": program_id, "amount": U128(amount), "balance": balance}),
        );
    }

    /// Program owner only. Sets open=false and refunds `balance`; `reserved` stays for pending
    /// claims. Callable again on a closed program to sweep funds returned by rejected claims.
    pub fn close_program(&mut self, program_id: u64) {
        let p = self.program_mut(program_id);
        Self::assert_program_owner(p);
        p.open = false;
        let refund = std::mem::replace(&mut p.balance, U128(0)).0;
        let owner = p.owner.clone();
        emit(
            "program_closed",
            json!({"program_id": program_id, "refund": U128(refund)}),
        );
        if refund > 0 {
            Promise::new(owner)
                .transfer(NearToken::from_yoctonear(refund))
                .detach();
        }
    }

    // ---------------- claims ----------------

    /// Payable: storage + `program.bond` (else "insufficient bond"); the rest is refunded.
    #[payable]
    #[allow(clippy::too_many_arguments)]
    pub fn submit_claim(
        &mut self,
        program_id: u64,
        req_hash: String,
        resp_body: Base64VecU8,
        signature: String,
        signer: Signer,
        kind: SigKind,
        ciphertext: String,
    ) -> u64 {
        let before = env::storage_usage();
        let attached = env::attached_deposit();
        let program = self
            .programs
            .get(&program_id)
            .unwrap_or_else(|| env::panic_str("program not found"));
        require!(program.open, "program closed");

        // v3 (#3): the signer must be in the program's own set (and still globally allowlisted).
        require!(program.signers.contains(&signer), "signer not allowlisted");
        let meta = self
            .signers
            .get(&signer)
            .unwrap_or_else(|| env::panic_str("signer not allowlisted"));
        require!(meta.kind == kind, "signer kind mismatch");

        if let Err(e) = tee::verify_tee_signature(
            &signer,
            kind,
            &program.model_id,
            &req_hash,
            &resp_body.0,
            &signature,
        ) {
            env::panic_str(&e);
        }
        let verdict = tee::parse_verdict(&resp_body.0).unwrap_or_else(|e| env::panic_str(&e));
        require!(
            verdict.valid
                && verdict.severity != Severity::None
                && verdict.confidence >= program.min_confidence,
            "verdict not payable"
        );

        // verify_tee_signature already validated it; normalise so case variants can't replay.
        let req_hash = tee::normalize_hash_hex(&req_hash).unwrap_or_else(|e| env::panic_str(&e));
        let key = dedupe_key(program_id, &req_hash);
        require!(!self.used_req_hashes.contains(&key), "already claimed");

        let payout = program.payouts.for_severity(verdict.severity);
        require!(payout <= program.balance.0, "insufficient pool");

        let now = env::block_timestamp();
        let finalize_after = now + program.dispute_secs * NANOS_PER_SEC;
        let model = program.model_id.clone();
        let bond = program.bond.0;

        let p = self.program_mut(program_id);
        p.balance = U128(p.balance.0 - payout);
        p.reserved = U128(p.reserved.0 + payout);

        let id = self.next_claim_id;
        self.next_claim_id += 1;
        let hunter = env::predecessor_account_id();
        let resp_hash = tee::sha256_hex(&resp_body.0);
        let severity = verdict.severity;
        self.used_req_hashes.insert(key);
        self.claims.insert(
            id,
            Claim {
                id,
                program_id,
                hunter: hunter.clone(),
                req_hash: req_hash.clone(),
                resp_hash,
                verdict,
                signer,
                kind,
                signature,
                model,
                ciphertext,
                status: ClaimStatus::Pending,
                payout: U128(payout),
                submitted_at: U64(now),
                finalize_after: U64(finalize_after),
                reject_reason: None,
                bond: U128(bond),
            },
        );
        let ids = self
            .claims_by_program
            .entry(program_id)
            .or_insert_with(|| Vector::new(StorageKey::ProgramClaims { program_id }));
        ids.push(id);
        ids.flush();
        self.claims_by_program.flush();
        self.programs.flush();
        self.claims.flush();

        let cost = charge_storage(before, attached);
        require!(
            attached.as_yoctonear() >= cost.as_yoctonear() + bond,
            "insufficient bond"
        );
        let refund = attached
            .saturating_sub(cost)
            .saturating_sub(NearToken::from_yoctonear(bond));
        if !refund.is_zero() {
            Promise::new(hunter.clone()).transfer(refund).detach();
        }
        emit(
            "claim_submitted",
            json!({
                "claim_id": id, "program_id": program_id, "hunter": hunter, "req_hash": req_hash,
                "severity": severity, "payout": U128(payout), "bond": U128(bond),
                "finalize_after": U64(finalize_after),
            }),
        );
        id
    }

    /// Program owner only, while the claim is Pending and the dispute window is open.
    /// Reveals the exact judge request body; rejects the claim if it was not the program's judge
    /// request for this hunter. On "hunter mismatch" (front-run) the req_hash is released so the
    /// real hunter can resubmit the same signed verdict.
    pub fn dispute(&mut self, claim_id: u64, request_body: String) {
        let claim = self
            .claims
            .get(&claim_id)
            .unwrap_or_else(|| env::panic_str("claim not found"));
        let program = self
            .programs
            .get(&claim.program_id)
            .expect("program exists");
        Self::assert_program_owner(program);
        require!(claim.status == ClaimStatus::Pending, "claim not pending");
        require!(
            env::block_timestamp() < claim.finalize_after.0,
            "dispute window closed"
        );
        require!(
            tee::sha256_hex(request_body.as_bytes()) == claim.req_hash,
            "body mismatch"
        );

        let reason = tamper_reason(program, &claim.hunter, &request_body)
            .unwrap_or_else(|| env::panic_str("dispute invalid: request matches program"));

        let (program_id, payout, bond) = (claim.program_id, claim.payout.0, claim.bond.0);
        if reason == HUNTER_MISMATCH {
            let key = dedupe_key(program_id, &claim.req_hash);
            self.used_req_hashes.remove(&key);
        }
        let c = self.claims.get_mut(&claim_id).unwrap();
        c.status = ClaimStatus::Rejected;
        c.reject_reason = Some(reason.to_string());
        let p = self.program_mut(program_id);
        p.reserved = U128(p.reserved.0 - payout);
        // Payout back to the pool; the hunter's bond is forfeited to it too.
        p.balance = U128(p.balance.0 + payout + bond);
        emit(
            "claim_rejected",
            json!({"claim_id": claim_id, "program_id": program_id, "reason": reason}),
        );
    }

    /// Anyone, once the dispute window has passed. Pays the hunter `payout + bond`, then
    /// `on_payout` credits it back to the program if the transfer failed. Rejects the claim with
    /// "signer revoked" if its signer was revoked meanwhile (#6; payout and bond go to the pool).
    pub fn finalize(&mut self, claim_id: u64) -> PromiseOrValue<()> {
        let c = self
            .claims
            .get_mut(&claim_id)
            .unwrap_or_else(|| env::panic_str("claim not found"));
        require!(c.status == ClaimStatus::Pending, "claim not pending");
        require!(
            env::block_timestamp() >= c.finalize_after.0,
            "dispute window open"
        );
        if self.revoked.contains(&c.signer) {
            c.status = ClaimStatus::Rejected;
            c.reject_reason = Some(SIGNER_REVOKED.to_string());
            let (program_id, payout, bond) = (c.program_id, c.payout.0, c.bond.0);
            let p = self.program_mut(program_id);
            p.reserved = U128(p.reserved.0 - payout);
            // Payout back to the pool; the hunter's bond is forfeited to it too (#4).
            p.balance = U128(p.balance.0 + payout + bond);
            emit(
                "claim_rejected",
                json!({"claim_id": claim_id, "program_id": program_id, "reason": SIGNER_REVOKED}),
            );
            return PromiseOrValue::Value(());
        }
        c.status = ClaimStatus::Paid;
        let (program_id, payout, bond, hunter) =
            (c.program_id, c.payout.0, c.bond.0, c.hunter.clone());
        let p = self.program_mut(program_id);
        p.reserved = U128(p.reserved.0 - payout);
        emit(
            "claim_paid",
            json!({"claim_id": claim_id, "program_id": program_id, "hunter": hunter, "payout": U128(payout), "bond": U128(bond)}),
        );
        Promise::new(hunter)
            .transfer(NearToken::from_yoctonear(payout + bond))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_ON_PAYOUT)
                    .on_payout(claim_id),
            )
            .into()
    }

    /// Callback of `finalize`'s transfer. On failure the transfer was refunded to this contract:
    /// mark the claim PayoutFailed and credit payout + bond back to the program balance, so the
    /// funds are not stranded. Returns whether the payout succeeded.
    #[private]
    pub fn on_payout(&mut self, claim_id: u64) -> bool {
        // A transfer has no return data; any non-empty result is still a success.
        if !matches!(env::promise_result_checked(0, 0), Err(PromiseError::Failed)) {
            return true;
        }
        let c = self
            .claims
            .get_mut(&claim_id)
            .unwrap_or_else(|| env::panic_str("claim not found"));
        require!(c.status == ClaimStatus::Paid, "claim not paid");
        c.status = ClaimStatus::PayoutFailed;
        let (program_id, amount, hunter) = (c.program_id, c.payout.0 + c.bond.0, c.hunter.clone());
        let p = self.program_mut(program_id);
        p.balance = U128(p.balance.0 + amount);
        emit(
            "payout_failed",
            json!({"claim_id": claim_id, "program_id": program_id, "hunter": hunter, "amount": U128(amount)}),
        );
        false
    }

    // ---------------- views ----------------

    pub fn get_program(&self, id: u64) -> Option<Program> {
        self.programs.get(&id).cloned()
    }

    /// Programs with id >= from_index (ids are sequential from 0), up to `limit` (default 50).
    pub fn list_programs(&self, from_index: Option<u64>, limit: Option<u64>) -> Vec<Program> {
        let from = from_index.unwrap_or(0);
        let limit = limit.unwrap_or(DEFAULT_LIMIT);
        (from..self.next_program_id)
            .filter_map(|id| self.programs.get(&id).cloned())
            .take(limit as usize)
            .collect()
    }

    pub fn get_claim(&self, id: u64) -> Option<Claim> {
        self.claims.get(&id).cloned()
    }

    /// Claims of `program_id` in submission order, skipping the first `from_index` of them, up to
    /// `limit` (default 50). Paginates the per-program index: cost is O(page), not O(all claims).
    pub fn list_claims(
        &self,
        program_id: u64,
        from_index: Option<u64>,
        limit: Option<u64>,
    ) -> Vec<Claim> {
        let Some(ids) = self.claims_by_program.get(&program_id) else {
            return vec![];
        };
        let len = u64::from(ids.len());
        let from = from_index.unwrap_or(0).min(len);
        let end = from.saturating_add(limit.unwrap_or(DEFAULT_LIMIT)).min(len);
        (from..end)
            .filter_map(|i| ids.get(i as u32))
            .filter_map(|id| self.claims.get(id).cloned())
            .collect()
    }

    // ---------------- debug ----------------

    /// Verify a TEE-signed chat completion and return the parsed verdict (no state change).
    /// Panics with "bad signature" if the signature does not match.
    pub fn verify_tee_response(
        &self,
        model: String,
        req_hash: String,
        resp_body: Base64VecU8,
        signature: String,
        signer: Signer,
        kind: SigKind,
    ) -> Verdict {
        let meta = self
            .signers
            .get(&signer)
            .unwrap_or_else(|| env::panic_str("signer not allowlisted"));
        require!(meta.kind == kind, "signer kind mismatch");

        if let Err(e) =
            tee::verify_tee_signature(&signer, kind, &model, &req_hash, &resp_body.0, &signature)
        {
            env::panic_str(&e);
        }
        let verdict = tee::parse_verdict(&resp_body.0).unwrap_or_else(|e| env::panic_str(&e));
        env::log_str(&format!(
            "verified {} sig; used_gas={}",
            match signer {
                Signer::Ed25519(_) => "ed25519",
                Signer::Eth(_) => "ecdsa",
            },
            env::used_gas().as_gas()
        ));
        verdict
    }
}

#[cfg(test)]
mod escrow_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::Severity;
    use near_sdk::serde::Deserialize;
    use near_sdk::serde_json;
    use near_sdk::test_utils::{VMContextBuilder, accounts};
    use near_sdk::testing_env;

    #[derive(Deserialize, Clone)]
    #[serde(crate = "near_sdk::serde")]
    struct Fixture {
        model: String,
        response_body_b64: String,
        req_hash: String,
        signature: String,
        signing_address: String,
        signing_algo: String,
        signature_kind: String,
    }

    impl Fixture {
        fn load(s: &str) -> Self {
            serde_json::from_str(s).unwrap()
        }
        fn signer(&self) -> Signer {
            let tagged = match self.signing_algo.as_str() {
                "ed25519" => format!("ed25519:{}", self.signing_address),
                "ecdsa" => format!("eth:{}", self.signing_address),
                a => panic!("algo {a}"),
            };
            Signer::try_from(tagged).unwrap()
        }
        fn kind(&self) -> SigKind {
            serde_json::from_value(serde_json::Value::String(self.signature_kind.clone())).unwrap()
        }
        fn body(&self) -> Base64VecU8 {
            serde_json::from_value(serde_json::Value::String(self.response_body_b64.clone()))
                .unwrap()
        }
    }

    const ED: &str = include_str!("../tests/fixtures/synthetic.ed25519.json");
    const EC: &str = include_str!("../tests/fixtures/synthetic.ecdsa.json");
    const GW: &str = include_str!("../tests/fixtures/synthetic.gateway.ecdsa.json");

    fn setup(fixtures: &[&Fixture]) -> Contract {
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(accounts(0))
                .build()
        );
        let mut c = Contract::new(None);
        for f in fixtures {
            c.add_signer(
                f.signer(),
                SignerMeta {
                    kind: f.kind(),
                    model: Some(f.model.clone()),
                },
            );
        }
        c
    }

    fn call(c: &Contract, f: &Fixture) -> Verdict {
        c.verify_tee_response(
            f.model.clone(),
            f.req_hash.clone(),
            f.body(),
            f.signature.clone(),
            f.signer(),
            f.kind(),
        )
    }

    #[test]
    fn signer_json_roundtrip() {
        let s: Signer =
            serde_json::from_str("\"eth:0xAbCdEf0000000000000000000000000000000001\"").unwrap();
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            "\"eth:0xabcdef0000000000000000000000000000000001\""
        );
        let e = Fixture::load(ED).signer();
        let back: Signer = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(e, back);
        assert!(serde_json::from_str::<Signer>("\"ed25519:abcd\"").is_err());
    }

    #[test]
    fn ed25519_ok() {
        let f = Fixture::load(ED);
        let c = setup(&[&f]);
        let v = call(&c, &f);
        assert_eq!(
            v,
            Verdict {
                valid: true,
                severity: Severity::High,
                cwe: Some("CWE-841".into()),
                confidence: 92
            }
        );
    }

    #[test]
    fn ecdsa_ok() {
        let f = Fixture::load(EC);
        let c = setup(&[&f]);
        let v = call(&c, &f);
        assert!(v.valid);
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn ecdsa_v_zero_one_ok() {
        let mut f = Fixture::load(EC);
        let c = setup(&[&f]);
        let mut sig = hex::decode(f.signature.trim_start_matches("0x")).unwrap();
        assert!(sig[64] == 27 || sig[64] == 28);
        sig[64] -= 27;
        f.signature = hex::encode(sig); // also no 0x prefix
        assert!(call(&c, &f).valid);
    }

    #[test]
    fn gateway_ok() {
        let f = Fixture::load(GW);
        assert_eq!(f.kind(), SigKind::Gateway);
        let c = setup(&[&f]);
        let v = call(&c, &f);
        assert_eq!(
            v,
            Verdict {
                valid: false,
                severity: Severity::None,
                cwe: None,
                confidence: 77
            }
        );
    }

    #[test]
    #[should_panic(expected = "bad signature")]
    fn ed25519_flipped_byte() {
        let mut f = Fixture::load(ED);
        let c = setup(&[&f]);
        let mut b = f.body().0;
        b[10] ^= 1;
        f.response_body_b64 = serde_json::to_value(Base64VecU8::from(b))
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        call(&c, &f);
    }

    #[test]
    #[should_panic(expected = "bad signature")]
    fn ecdsa_flipped_byte() {
        let mut f = Fixture::load(EC);
        let c = setup(&[&f]);
        let mut b = f.body().0;
        b[10] ^= 1;
        f.response_body_b64 = serde_json::to_value(Base64VecU8::from(b))
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        call(&c, &f);
    }

    #[test]
    #[should_panic(expected = "bad signature")]
    fn ed25519_wrong_model() {
        let mut f = Fixture::load(ED);
        let c = setup(&[&f]);
        f.model = "openai/gpt-oss-120b".into();
        call(&c, &f);
    }

    #[test]
    #[should_panic(expected = "bad signature")]
    fn ecdsa_wrong_model() {
        let mut f = Fixture::load(EC);
        let c = setup(&[&f]);
        f.model = "openai/gpt-oss-120b".into();
        call(&c, &f);
    }

    #[test]
    #[should_panic(expected = "signer not allowlisted")]
    fn not_allowlisted() {
        let f = Fixture::load(EC);
        let c = setup(&[&Fixture::load(ED)]);
        call(&c, &f);
    }

    #[test]
    #[should_panic(expected = "signer kind mismatch")]
    fn kind_mismatch() {
        let f = Fixture::load(GW);
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(accounts(0))
                .build()
        );
        let mut c = Contract::new(None);
        c.add_signer(
            f.signer(),
            SignerMeta {
                kind: SigKind::ProviderTee,
                model: None,
            },
        );
        call(&c, &f);
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn add_signer_owner_only() {
        let f = Fixture::load(ED);
        let mut c = setup(&[]);
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(accounts(1))
                .build()
        );
        c.add_signer(
            f.signer(),
            SignerMeta {
                kind: SigKind::ProviderTee,
                model: None,
            },
        );
    }

    #[test]
    #[should_panic(expected = "signer not allowlisted")]
    fn removed_signer_rejected() {
        let f = Fixture::load(ED);
        let mut c = setup(&[&f]);
        assert!(c.remove_signer(f.signer()));
        call(&c, &f);
    }

    #[test]
    fn fence_and_prose_parsing() {
        let wrap = |content: &str| {
            serde_json::json!({"choices":[{"message":{"role":"assistant","content":content}}]})
                .to_string()
        };
        let raw = r#"{"valid":true,"severity":"critical","cwe":"CWE-89","confidence":100}"#;
        for c in [
            raw.to_string(),
            format!("```json\n{raw}\n```"),
            format!("```\n{raw}\n```"),
            format!("Here you go:\n{raw}\nThanks"),
        ] {
            let v = tee::parse_verdict(wrap(&c).as_bytes()).unwrap();
            assert_eq!(v.severity, Severity::Critical);
        }
        assert!(
            tee::parse_verdict(
                wrap(r#"{"valid":true,"severity":"huge","confidence":1}"#).as_bytes()
            )
            .is_err()
        );
        assert!(tee::parse_verdict(b"{\"choices\":[]}").is_err());
    }
}
