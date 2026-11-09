// CORS: the only browser origin allowed to drive the helper is the local Vite dev server.
export const ALLOWED_ORIGIN = 'http://localhost:5173';

/** No Origin header = a non-browser client (curl). Browsers always send Origin on cross-origin requests. */
export const originAllowed = (origin) => origin === undefined || origin === ALLOWED_ORIGIN;

export function corsHeaders(origin) {
  const h = { Vary: 'Origin' };
  if (origin === ALLOWED_ORIGIN) h['Access-Control-Allow-Origin'] = ALLOWED_ORIGIN;
  return h;
}

export const PREFLIGHT_HEADERS = {
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'content-type',
  'Access-Control-Max-Age': '600',
};
