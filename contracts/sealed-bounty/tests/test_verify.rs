//! Sandbox integration test: deploy, allowlist signers, verify TEE-signed fixtures onchain.

use near_api::{AccountId, NearGas, NearToken};
use near_sdk::serde_json::{self, Value, json};
use sealed_bounty::Verdict;

struct Fx(Value);

impl Fx {
    fn load(name: &str) -> Self {
        let p = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        Fx(serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
    }
    fn s(&self, k: &str) -> String {
        self.0[k].as_str().unwrap().to_string()
    }
    fn signer(&self) -> String {
        match self.s("signing_algo").as_str() {
            "ed25519" => format!("ed25519:{}", self.s("signing_address")),
            "ecdsa" => format!("eth:{}", self.s("signing_address")),
            a => panic!("algo {a}"),
        }
    }
    fn args(&self) -> Value {
        json!({
            "model": self.s("model"),
            "req_hash": self.s("req_hash"),
            "resp_body": self.s("response_body_b64"),
            "signature": self.s("signature"),
            "signer": self.signer(),
            "kind": self.s("signature_kind"),
        })
    }
}

fn b64(bytes: &[u8]) -> String {
    serde_json::to_value(near_sdk::json_types::Base64VecU8::from(bytes.to_vec()))
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn verify_tee_response_on_sandbox() -> testresult::TestResult<()> {
    let wasm_path = cargo_near_build::build_with_cli(Default::default())?;
    let wasm = std::fs::read(&wasm_path)?;
    println!("wasm size: {} bytes", wasm.len());

    let sandbox = near_sandbox::Sandbox::start_sandbox().await?;
    let net = near_api::NetworkConfig::from_rpc_url("sandbox", sandbox.rpc_addr.parse()?);
    let signer = near_api::Signer::from_secret_key(
        near_sandbox::config::DEFAULT_GENESIS_ACCOUNT_PRIVATE_KEY
            .parse()
            .unwrap(),
    )?;

    let owner = create_subaccount(&sandbox, "owner.sandbox").await?;
    let contract = create_subaccount(&sandbox, "contract.sandbox")
        .await?
        .as_contract();

    near_api::Contract::deploy(contract.account_id().clone())
        .use_code(wasm)
        .with_init_call("new", json!({ "owner": owner.account_id() }))?
        .with_signer(signer.clone())
        .send_to(&net)
        .await?
        .assert_success();

    let ed = Fx::load("synthetic.ed25519.json");
    let ec = Fx::load("synthetic.ecdsa.json");
    let gw = Fx::load("synthetic.gateway.ecdsa.json");

    for f in [&ed, &ec, &gw] {
        contract
            .call_function(
                "add_signer",
                json!({ "signer": f.signer(), "meta": { "kind": f.s("signature_kind"), "model": f.s("model") } }),
            )
            .transaction()
            .with_signer(owner.account_id().clone(), signer.clone())
            .send_to(&net)
            .await?
            .assert_success();
    }

    let call = |args: Value| {
        let contract = contract.clone();
        let signer = signer.clone();
        let who = owner.account_id().clone();
        let net = net.clone();
        async move {
            contract
                .call_function("verify_tee_response", args)
                .transaction()
                .gas(NearGas::from_tgas(300))
                .with_signer(who, signer)
                .send_to(&net)
                .await
                .unwrap()
        }
    };

    // --- free view call (the guided tour's "Ask the contract") ---
    // verify_tee_response must be callable through RPC `call_function` as a view: no gas, no signer.
    // Views on NEAR prohibit env::used_gas() and other runtime-context host fns.
    for (label, f) in [("ed25519", &ed), ("ecdsa", &ec)] {
        let v: near_api::Data<Verdict> = contract
            .call_function("verify_tee_response", f.args())
            .read_only()
            .fetch_from(&net)
            .await
            .unwrap_or_else(|e| panic!("view verify_tee_response ({label}) failed: {e:?}"));
        println!("[OK] view verify_tee_response {label}: verdict = {:?}", v.data);
        assert!(v.data.valid, "{label}: view verdict should be valid");
    }

    // --- success paths ---
    for (label, args) in [
        ("ed25519/provider_tee", ed.args()),
        ("ecdsa/provider_tee", ec.args()),
        ("ecdsa/gateway", gw.args()),
        ("ecdsa/provider_tee v=0|1", {
            let mut a = ec.args();
            let mut sig = hex::decode(ec.s("signature").trim_start_matches("0x")).unwrap();
            sig[64] -= 27;
            a["signature"] = json!(hex::encode(sig));
            a
        }),
    ] {
        let ok = call(args).await.assert_success();
        let burnt = ok.total_gas_burnt;
        let logs: Vec<String> = ok.logs().into_iter().map(String::from).collect();
        let v: Verdict = ok.json()?;
        println!(
            "[OK] {label}: total_gas_burnt = {:.3} Tgas ({} gas); logs = {:?}; verdict = {:?}",
            burnt.as_gas() as f64 / 1e12,
            burnt.as_gas(),
            logs,
            v
        );
    }

    // --- negatives ---
    let expect_fail = |label: &'static str, args: Value, needle: &'static str| {
        let call = &call;
        async move {
            let err = call(args).await.assert_failure();
            let msg = format!("{err:?}");
            assert!(
                msg.contains(needle),
                "{label}: expected '{needle}' in {msg}"
            );
            println!("[FAIL as expected] {label}: '{needle}'");
        }
    };

    for f in [&ed, &ec] {
        let mut body = near_sdk::base64::Engine::decode(
            &near_sdk::base64::engine::general_purpose::STANDARD,
            f.s("response_body_b64"),
        )?;
        body[10] ^= 1;
        let mut a = f.args();
        a["resp_body"] = json!(b64(&body));
        expect_fail("flipped response byte", a, "bad signature").await;

        let mut a = f.args();
        a["model"] = json!("openai/gpt-oss-120b");
        expect_fail("wrong model", a, "bad signature").await;
    }

    let mut a = gw.args();
    a["kind"] = json!("provider_tee");
    expect_fail("gateway sig as provider_tee", a, "signer kind mismatch").await;

    // remove ed25519 signer -> not allowlisted
    contract
        .call_function("remove_signer", json!({ "signer": ed.signer() }))
        .transaction()
        .with_signer(owner.account_id().clone(), signer.clone())
        .send_to(&net)
        .await?
        .assert_success();
    expect_fail(
        "signer not allowlisted",
        ed.args(),
        "signer not allowlisted",
    )
    .await;

    // non-owner cannot add signers
    contract
        .call_function(
            "add_signer",
            json!({ "signer": ed.signer(), "meta": { "kind": "provider_tee", "model": null } }),
        )
        .transaction()
        .with_signer(contract.account_id().clone(), signer.clone())
        .send_to(&net)
        .await?
        .assert_failure();

    Ok(())
}

async fn create_subaccount(
    sandbox: &near_sandbox::Sandbox,
    name: &str,
) -> testresult::TestResult<near_api::Account> {
    let account_id: AccountId = name.parse().unwrap();
    sandbox
        .create_account(account_id.as_str().parse()?)
        .initial_balance(NearToken::from_near(10))
        .send()
        .await?;
    Ok(near_api::Account(account_id))
}
