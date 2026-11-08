import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import { verifyMessage } from 'ethers';

export const sha256hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
const strip0x = (h) => (h.startsWith('0x') || h.startsWith('0X') ? h.slice(2) : h);
export const normAddr = (h) => strip0x(String(h)).toLowerCase();
const hexBuf = (h) => Buffer.from(strip0x(h), 'hex');

export function inferKind(text) {
  return text.split(':').length >= 3 ? 'provider_tee' : 'gateway';
}

export function expectedText(kind, model, reqHash, respHash) {
  return kind === 'provider_tee' ? `${model}:${reqHash}:${respHash}` : `${reqHash}:${respHash}`;
}

export function verifySig({ text, signature, signing_address, signing_algo }) {
  if (signing_algo === 'ed25519') {
    const pk = hexBuf(signing_address);
    const sig = hexBuf(signature);
    if (pk.length !== 32) throw new Error(`ed25519 pubkey len ${pk.length}`);
    if (sig.length !== 64) throw new Error(`ed25519 sig len ${sig.length}`);
    return nacl.sign.detached.verify(Buffer.from(text, 'utf8'), sig, pk);
  }
  if (signing_algo === 'ecdsa') {
    const sigHex = '0x' + strip0x(signature);
    const rec = verifyMessage(text, sigHex);
    return normAddr(rec) === normAddr(signing_address);
  }
  throw new Error(`unknown algo ${signing_algo}`);
}

/** Full offline check of a fixture object. Returns list of [name, ok, detail]. */
export function checkFixture(f) {
  const reqBytes = Buffer.from(f.request_body, 'utf8');
  const respBytes = Buffer.from(f.response_body_b64, 'base64');
  const reqHash = sha256hex(reqBytes);
  const respHash = sha256hex(respBytes);
  const model = JSON.parse(f.request_body).model;
  const kind = f.signature_kind;
  const exp = expectedText(kind, f.model, reqHash, respHash);
  let sigOk = false, sigErr = '';
  try { sigOk = verifySig(f); } catch (e) { sigErr = e.message; }
  let respId = null;
  try { respId = JSON.parse(respBytes.toString('utf8')).id; } catch {}
  return [
    ['req_hash matches request_body', reqHash === f.req_hash, reqHash],
    ['resp_hash matches response bytes', respHash === f.resp_hash, respHash],
    ['request model == fixture model', model === f.model, model],
    ['chat_id == response id', respId === f.chat_id, respId],
    ['kind consistent with text shape', inferKind(f.text) === kind, kind],
    ['text == expected from our hashes', f.text === exp, exp],
    [`${f.signing_algo} signature verifies`, sigOk, sigErr || f.signing_address],
    ['signer_in_attestation', f.signer_in_attestation === true, String(f.signer_in_attestation)],
  ];
}
