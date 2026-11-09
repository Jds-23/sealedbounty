// The demo-helper client must tolerate how the SSE stream is chunked and stray lines (docs/demo-app-spec.md §8).
import { describe, expect, it } from 'vitest';
import { parseSSE } from './helper';

describe('helper SSE parser', () => {
  it('parses data: events split across chunks and keeps the incomplete tail', () => {
    const a = parseSSE('data: {"step":"submit_claim","status":"pending"}\n\ndata: {"step":"submit_cl');
    expect(a.events).toEqual([{ step: 'submit_claim', status: 'pending' }]);
    const b = parseSSE(a.rest + 'aim","status":"done","tx":"ABC","claimId":7}\n\n');
    expect(b.events).toEqual([{ step: 'submit_claim', status: 'done', tx: 'ABC', claimId: 7 }]);
    expect(b.rest).toBe('');
  });

  it('ignores comments, event:/id: lines and junk; accepts bare JSON lines and CRLF', () => {
    const r = parseSSE(': keepalive\r\nevent: progress\r\nid: 3\r\ndata: {"step":"end","outcome":"Paid"}\r\n\r\n{"step":"x","status":"done"}\nnot json\n\n');
    expect(r.events).toEqual([
      { step: 'end', outcome: 'Paid' },
      { step: 'x', status: 'done' },
    ]);
  });
});
