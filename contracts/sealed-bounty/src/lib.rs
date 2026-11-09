//! SealedBounty escrow: bug-bounty programs paid out on NEAR AI Cloud TEE-signed judge verdicts.
//! Spec: docs/INTERFACE.md (binding).

pub mod tee;

use near_sdk::json_types::{Base64VecU8, U64, U128};
use near_sdk::serde::Deserialize;
use near_sdk::serde_json::{self, json};
use near_sdk::store::{IterableMap, LookupSet};
use near_sdk::{
    AccountId, BorshStorageKey, NearToken, PanicOnDefault, Promise, env, near, require,
};

use tee::Severity;
pub use tee::{SigKind, Signer, Verdict};

const NANOS_PER_SEC: u64 = 1_000_000_000;
const DEFAULT_LIMIT: u64 = 50;

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerMeta {
    pub kind: SigKind,
    /// Informational: which model this provider key serves (not enforced; the signed text binds the model).
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
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner: AccountId,
    signers: IterableMap<Signer, SignerMeta>,
    programs: IterableMap<u64, Program>,
    claims: IterableMap<u64, Claim>,
    used_req_hashes: LookupSet<String>,
    next_program_id: u64,
    next_claim_id: u64,
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

/// Minimal shape of the canonical judge request (unknown fields ignored).
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

pub(crate) const TAMPERED: &str = "system prompt tampered";
pub(crate) const MODEL_MISMATCH: &str = "model mismatch";
pub(crate) const CODE_MISMATCH: &str = "code mismatch";
pub(crate) const HUNTER_MISMATCH: &str = "hunter mismatch";
pub(crate) const REPORT_MISSING: &str = "report missing";

/// `None` if the revealed request matches the program and the claim's hunter, else the FIRST
/// failing reject reason (INTERFACE.md v2 order):
/// 1. system prompt tampered (also: not JSON, or more than 3 messages)
/// 2. model mismatch
/// 3. code mismatch (messages[1] role/TARGET line/CODE framing/code hash)
/// 4. hunter mismatch (only the HUNTER line differs from `hunter`)
/// 5. report missing
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
            used_req_hashes: LookupSet::new(StorageKey::UsedReqHashes),
            next_program_id: 0,
            next_claim_id: 0,
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
        payouts: Payouts,
        owner_enc_pubkey: String,
        dispute_secs: u64,
        min_confidence: u8,
        bond: U128,
    ) -> u64 {
        let system_prompt_hash = tee::normalize_hash_hex(&system_prompt_hash)
            .unwrap_or_else(|_| env::panic_str("system_prompt_hash must be 64 hex chars"));
        let code_hash = tee::normalize_hash_hex(&code_hash)
            .unwrap_or_else(|_| env::panic_str("code_hash must be 64 hex chars"));
        require!(min_confidence <= 100, "min_confidence must be <= 100");
        require!(
            dispute_secs.checked_mul(NANOS_PER_SEC).is_some(),
            "dispute_secs too large"
        );

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
        require!(!self.used_req_hashes.contains(&req_hash), "already claimed");

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
        self.used_req_hashes.insert(req_hash.clone());
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
            let req_hash = claim.req_hash.clone();
            self.used_req_hashes.remove(&req_hash);
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

    /// Anyone, once the dispute window has passed. Pays the hunter `payout + bond`.
    pub fn finalize(&mut self, claim_id: u64) -> Promise {
        let c = self
            .claims
            .get_mut(&claim_id)
            .unwrap_or_else(|| env::panic_str("claim not found"));
        require!(c.status == ClaimStatus::Pending, "claim not pending");
        require!(
            env::block_timestamp() >= c.finalize_after.0,
            "dispute window open"
        );
        c.status = ClaimStatus::Paid;
        let (program_id, payout, bond, hunter) =
            (c.program_id, c.payout.0, c.bond.0, c.hunter.clone());
        let p = self.program_mut(program_id);
        p.reserved = U128(p.reserved.0 - payout);
        emit(
            "claim_paid",
            json!({"claim_id": claim_id, "program_id": program_id, "hunter": hunter, "payout": U128(payout), "bond": U128(bond)}),
        );
        Promise::new(hunter).transfer(NearToken::from_yoctonear(payout + bond))
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

    /// Claims of `program_id`, skipping the first `from_index` of them, up to `limit` (default 50).
    pub fn list_claims(
        &self,
        program_id: u64,
        from_index: Option<u64>,
        limit: Option<u64>,
    ) -> Vec<Claim> {
        self.claims
            .values()
            .filter(|c| c.program_id == program_id)
            .skip(from_index.unwrap_or(0) as usize)
            .take(limit.unwrap_or(DEFAULT_LIMIT) as usize)
            .cloned()
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
