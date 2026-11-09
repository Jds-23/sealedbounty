// #13: the "payout tx" link must only point at a finalize that actually emitted claim_paid for that claim.
// Replays recorded real responses (src/fixtures/finalize-txs.json) from sealedbounty-v3.testnet through a mocked fetch.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import rec from '../fixtures/finalize-txs.json';

const PAID = 'ATvCo4xULdHdpGBJp1NErtptgB9RjrgGHNrBUaUic6Kz'; // claim 0, claim_paid
const REJECTED = '2Cfo4ueWH6udU8oKw7jAYnJxmYSGAGYvBFszCdcwwvCt'; // claim 4, claim_rejected "undecryptable report"

const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });

function recordedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = String(input);
  if (url.includes('api-testnet.nearblocks.io')) {
    if (/\/accounts\/[^/]+\/txns/.test(url)) return Promise.resolve(json(rec.nearblocks.list));
    const h = url.match(/\/txns\/([^/?]+)$/)?.[1] as keyof typeof rec.nearblocks.txns | undefined;
    if (h && rec.nearblocks.txns[h]) return Promise.resolve(json(rec.nearblocks.txns[h]));
    return Promise.resolve(new Response('not found', { status: 404 }));
  }
  const body = JSON.parse(String(init?.body ?? '{}'));
  if (body.method === 'tx') {
    const h = (Array.isArray(body.params) ? body.params[0] : body.params?.tx_hash) as keyof typeof rec.rpc_tx;
    const r = rec.rpc_tx[h];
    return Promise.resolve(json(r ? { jsonrpc: '2.0', id: body.id, ...r } : { jsonrpc: '2.0', id: body.id, error: { message: 'UNKNOWN_TRANSACTION' } }));
  }
  return Promise.resolve(new Response('unexpected', { status: 500 }));
}

describe('findPaidTxs (#13)', () => {
  beforeEach(() => {
    vi.resetModules(); // findPaidTxs caches per module
    vi.stubGlobal('fetch', vi.fn(recordedFetch));
  });
  afterEach(() => vi.unstubAllGlobals());

  it('links the claim_paid finalize for claim 0 but not the claim_rejected finalize for claim 4', async () => {
    const { findPaidTxs } = await import('./near');
    const txs = await findPaidTxs();
    expect(txs[0]).toBe(PAID);
    expect(txs[4]).toBeUndefined();
    expect(Object.values(txs)).not.toContain(REJECTED);
    expect(txs).toEqual({ 0: PAID });
  });
});

describe('paidClaimIds (#13)', () => {
  it('reads claim_paid from the recorded claim 0 finalize', async () => {
    const { paidClaimIds } = await import('./near');
    expect(paidClaimIds(rec.rpc_tx[PAID].result)).toEqual([0]);
  });

  it('ignores the recorded claim_rejected finalize for claim 4', async () => {
    const { paidClaimIds } = await import('./near');
    expect(paidClaimIds(rec.rpc_tx[REJECTED].result)).toEqual([]);
  });

  it('drops a claim whose payout_failed in the same tx, logs of failed receipts, and foreign events', async () => {
    const { paidClaimIds } = await import('./near');
    const ev = (event: string, claim_id: number, standard = 'sealedbounty') =>
      `EVENT_JSON:${JSON.stringify({ standard, version: '1.0.0', event, data: [{ claim_id }] })}`;
    const tx = {
      receipts_outcome: [
        { outcome: { status: { SuccessReceiptId: 'x' }, logs: [ev('claim_paid', 7), ev('claim_paid', 8)] } },
        { outcome: { status: { SuccessValue: '' }, logs: [ev('payout_failed', 8)] } },
        { outcome: { status: { Failure: {} }, logs: [ev('claim_paid', 9)] } },
        { outcome: { status: { SuccessValue: '' }, logs: ['EVENT_JSON:{bad', ev('claim_paid', 10, 'other')] } },
      ],
    };
    expect(paidClaimIds(tx)).toEqual([7]);
  });
});
