// Server-sent events over a plain node:http response. Each event is one `data: <json>` line
// followed by a blank line; JSON.stringify escapes newlines, so a frame never splits.

export const sseFrame = (event) => `data: ${JSON.stringify(event)}\n\n`;

/**
 * Starts an SSE response. `send` is a no-op once the client has gone away: the helper keeps
 * driving the chain to a settled state instead of leaving a claim half way (e.g. Challenged).
 * @param {import('node:http').ServerResponse} res
 * @param {{headers?: Record<string,string>, transform?: (e: object) => object, heartbeatMs?: number}} [opts]
 */
export function openSse(res, { headers = {}, transform = (e) => e, heartbeatMs = 15_000 } = {}) {
  res.writeHead(200, {
    ...headers,
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders?.();
  let closed = false;
  // comment frames keep proxies/fetch readers from timing out during a long TEE call
  const beat = setInterval(() => !closed && !res.writableEnded && res.write(': ping\n\n'), heartbeatMs);
  beat.unref?.();
  res.on('close', () => {
    closed = true;
    clearInterval(beat);
  });
  return {
    send(event) {
      if (!closed && !res.writableEnded) res.write(sseFrame(transform(event)));
    },
    end() {
      clearInterval(beat);
      if (!res.writableEnded) res.end();
    },
  };
}
