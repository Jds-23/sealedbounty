// Step 5 'Ask the contract' (docs/demo-app-spec.md §5): a free RPC view of verify_tee_response on claim #0's
// submit_claim args. fetch is mocked with real responses recorded from https://test.rpc.fastnear.com
// (src/fixtures/verify-tee-response.rpc.json): the original resp_body returns the Verdict, a 1-byte flip panics
// "bad signature". Any transport failure falls back to the snapshot, flagged.
import { afterEach, describe, expect, it, vi } from 'vitest';
import rec from '../fixtures/verify-tee-response.rpc.json';
import { askContract, askContractArgs, claimTxs, snapshotData } from './tourData';
import { flipIndex } from './steps/Step5';

const RPC = { urls: ['https://rpc.example.test'], timeoutMs: 1000 };
const d = snapshotData();
const claim = d.claims.find((c) => c.id === 0)!;
const submit = claimTxs(d.txs, claim).submit!;
const respB64 = submit.args!.resp_body as string;

const flippedB64 = () => {
  const body = Uint8Array.from(atob(respB64), (c) => c.charCodeAt(0));
  const i = flipIndex(body);
  body[i] ^= 0x01;
  return { i, b64: btoa(String.fromCharCode(...body)) };
};

/** Mocks fetch with one recorded JSON-RPC response and captures the sent view args. */
function mockRpc(response: unknown) {
  const sent: any[] = [];
  const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    sent.push({ ...body, args: JSON.parse(atob(body.params.args_base64)) });
    return new Response(JSON.stringify(response), { status: 200, headers: { 'content-type': 'application/json' } });
  });
  vi.stubGlobal('fetch', fetchMock);
  return sent;
}

afterEach(() => vi.unstubAllGlobals());

describe('askContractArgs', () => {
  it("builds verify_tee_response args from claim #0's submit_claim tx", () => {
    const a = askContractArgs(claim, submit);
    expect(a).toEqual({
      model: claim.model,
      req_hash: submit.args!.req_hash,
      resp_body: respB64,
      signature: submit.args!.signature,
      signer: submit.args!.signer,
      kind: submit.args!.kind,
    });
    expect(a.signer).toMatch(/^ed25519:[0-9a-f]{64}$/);
    expect(a.signature).toMatch(/^[0-9a-f]{128}$/);
  });

  it('takes an override resp_body (the flipped-byte variant)', () => {
    const f = flippedB64();
    expect(f.i).toBe(rec.flipped.flipped_index);
    expect(askContractArgs(claim, submit, f.b64).resp_body).toBe(f.b64);
  });
});

describe('askContract (RPC call_function verify_tee_response)', () => {
  it("success: returns the contract's own Verdict, live", async () => {
    const sent = mockRpc(rec.ok.response);
    const r = await askContract(askContractArgs(claim, submit), RPC);
    expect(r).toEqual({
      ok: true,
      verdict: { valid: true, severity: 'critical', cwe: 'CWE-89', confidence: 100 },
      source: 'live',
      rpcError: null,
    });
    expect(sent).toHaveLength(1);
    expect(sent[0].method).toBe('query');
    expect(sent[0].params).toMatchObject({ request_type: 'call_function', method_name: 'verify_tee_response', account_id: 'sealedbounty-v3.testnet' });
    expect(sent[0].args).toEqual(askContractArgs(claim, submit));
  });

  it('flipped byte: returns the panic message "bad signature", live', async () => {
    const sent = mockRpc(rec.flipped.response);
    const r = await askContract(askContractArgs(claim, submit, flippedB64().b64), RPC);
    expect(r).toEqual({ ok: false, error: 'bad signature', source: 'live', rpcError: null });
    expect(sent).toHaveLength(1); // a contract panic is final: no retry on the next RPC
  });

  it('parses a panic delivered as a top-level JSON-RPC error too', async () => {
    mockRpc({
      jsonrpc: '2.0',
      id: 'sb',
      error: { name: 'HANDLER_ERROR', cause: { name: 'CONTRACT_EXECUTION_ERROR', info: { vm_error: 'wasm execution failed with error: HostError(GuestPanic { panic_msg: "signer not allowlisted" })' } }, code: -32000, message: 'Server error', data: 'wasm execution failed with error: HostError(GuestPanic { panic_msg: "signer not allowlisted" })' },
    });
    const r = await askContract(askContractArgs(claim, submit), RPC);
    expect(r).toMatchObject({ ok: false, error: 'signer not allowlisted', source: 'live' });
  });

  it('RPC failure: falls back to the snapshot (claim #0 verdict), flagged', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('busy', { status: 503 })));
    const r = await askContract(askContractArgs(claim, submit), RPC);
    expect(r.source).toBe('snapshot');
    expect(r.rpcError).toMatch(/503/);
    expect(r).toMatchObject({ ok: true, verdict: claim.verdict });
  });

  it('RPC failure on the flipped variant: snapshot answer is "bad signature", flagged', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Promise.reject(new TypeError('Failed to fetch'))));
    const r = await askContract(askContractArgs(claim, submit, flippedB64().b64), RPC);
    expect(r).toMatchObject({ ok: false, error: 'bad signature', source: 'snapshot' });
    expect(r.rpcError).toMatch(/Failed to fetch/);
  });
});
