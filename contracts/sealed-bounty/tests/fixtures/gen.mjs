// Generates SYNTHETIC NEAR AI Cloud-style signed chat completion fixtures.
//
// Output shape (same as the live recorder will write, so real fixtures drop in):
// {
//   model, request_body, response_body_b64, req_hash,
//   signature, signing_address, signing_algo, signature_kind
// }
//
// Signed text:
//   provider_tee: `${model}:${sha256hex(request_body)}:${sha256hex(response_body)}`
//   gateway:      `${sha256hex(request_body)}:${sha256hex(response_body)}`
//
// ed25519: tweetnacl detached sig over UTF-8 text; signing_address = 32-byte pubkey hex.
// ecdsa:   ethers wallet.signMessage(text) (EIP-191, v = 27/28); signing_address = 0x address.
//
// Usage: node gen.mjs   (writes synthetic.*.json next to this file)

import { createHash, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import nacl from "tweetnacl";
import { Wallet } from "ethers";

const here = dirname(fileURLToPath(import.meta.url));
const sha256hex = (buf) => createHash("sha256").update(buf).digest("hex");
const hex = (u8) => Buffer.from(u8).toString("hex");

const MODEL = "deepseek-ai/DeepSeek-V3.1";

function makeBodies(verdict) {
  const request = {
    model: MODEL,
    messages: [
      {
        role: "system",
        content:
          "You are a security triage judge. Reply ONLY with JSON: " +
          '{"valid": bool, "severity": "none|low|medium|high|critical", "cwe": string|null, "confidence": 0-100}',
      },
      {
        role: "user",
        content:
          "Bounty: reentrancy in withdraw(). Report: withdraw() sends ETH via call before zeroing balance; PoC attached.",
      },
    ],
    temperature: 0,
    stream: false,
  };
  const content = "```json\n" + JSON.stringify(verdict, null, 2) + "\n```";
  const response = {
    id: "chatcmpl-" + randomBytes(12).toString("hex"),
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: MODEL,
    choices: [
      {
        index: 0,
        message: { role: "assistant", content, tool_calls: [] },
        logprobs: null,
        finish_reason: "stop",
      },
    ],
    usage: { prompt_tokens: 112, completion_tokens: 41, total_tokens: 153 },
  };
  // Exact raw bytes matter: these strings are what get hashed.
  return { request_body: JSON.stringify(request), response_body: JSON.stringify(response) };
}

function fixture({ kind, algo, verdict }) {
  const { request_body, response_body } = makeBodies(verdict);
  const reqHex = sha256hex(Buffer.from(request_body, "utf8"));
  const respHex = sha256hex(Buffer.from(response_body, "utf8"));
  const text = kind === "provider_tee" ? `${MODEL}:${reqHex}:${respHex}` : `${reqHex}:${respHex}`;
  return { request_body, response_body, reqHex, text };
}

async function main() {
  const verdict = { valid: true, severity: "high", cwe: "CWE-841", confidence: 92 };
  const outputs = [];

  // ed25519 / provider_tee
  {
    const f = fixture({ kind: "provider_tee", algo: "ed25519", verdict });
    const kp = nacl.sign.keyPair();
    const sig = nacl.sign.detached(Buffer.from(f.text, "utf8"), kp.secretKey);
    outputs.push(["synthetic.ed25519.json", {
      model: MODEL,
      request_body: f.request_body,
      response_body_b64: Buffer.from(f.response_body, "utf8").toString("base64"),
      req_hash: f.reqHex,
      signature: hex(sig),
      signing_address: hex(kp.publicKey),
      signing_algo: "ed25519",
      signature_kind: "provider_tee",
    }]);
  }

  // ecdsa / provider_tee and ecdsa / gateway
  for (const [file, kind, v] of [
    ["synthetic.ecdsa.json", "provider_tee", verdict],
    ["synthetic.gateway.ecdsa.json", "gateway", { valid: false, severity: "none", cwe: null, confidence: 77 }],
  ]) {
    const f = fixture({ kind, algo: "ecdsa", verdict: v });
    const wallet = Wallet.createRandom();
    const sig = await wallet.signMessage(f.text); // 0x r||s||v, v = 27/28
    outputs.push([file, {
      model: MODEL,
      request_body: f.request_body,
      response_body_b64: Buffer.from(f.response_body, "utf8").toString("base64"),
      req_hash: f.reqHex,
      signature: sig,
      signing_address: wallet.address,
      signing_algo: "ecdsa",
      signature_kind: kind,
    }]);
  }

  for (const [file, obj] of outputs) {
    writeFileSync(join(here, file), JSON.stringify(obj, null, 2) + "\n");
    console.log("wrote", file, obj.signing_algo, obj.signature_kind, obj.signing_address);
  }
}

main();
