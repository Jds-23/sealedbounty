// Issue #1 (INTERFACE.md v3 "#1 params pinning"): the request params are pinned by
// program.params_hash, and the request must have exactly the canonical keys.
// Run: pnpm test (node --test).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as judge from '../judge.mjs';
import { DEMO_TARGET, DEMO_HUNTER } from '../demo-data.mjs';

const { checkRequestAgainstProgram, systemPromptHash, DEFAULT_MODEL } = judge;
const here = (p) => new URL(p, import.meta.url);
const fixture = (name) => JSON.parse(readFileSync(here(`../../fixtures/demo.${name}.json`), 'utf8'));
const bundleHash = readFileSync(here('../../fixtures/vuln-app/bundle.sha256'), 'utf8').trim();

/** sha256hex(canonicalJson(params)) of the honest demo request; the contract test pins the same hex. */
const DEMO_PARAMS_HASH = '61b52e7b87e42a2bc4b6f417d21ba0e9d44f3e1f4ff49fa9d2f3334e5aa0eda7';

const program = {
  repo_url: DEMO_TARGET.repoUrl, commit: DEMO_TARGET.commit, model_id: DEFAULT_MODEL,
  system_prompt_hash: systemPromptHash(), code_hash: bundleHash, params_hash: DEMO_PARAMS_HASH,
};
const honest = fixture('sqli').request_body;
const mutate = (f) => { const r = JSON.parse(honest); f(r); return JSON.stringify(r); };

test('honest demo request matches the program', () => {
  assert.deepEqual(checkRequestAgainstProgram(honest, program, DEMO_HUNTER), { ok: true, reason: null });
});

const TAMPERED = {
  'response_format forces valid:true / critical / confidence 100': mutate((r) => {
    const s = r.response_format.json_schema.schema;
    s.properties.valid = { type: 'boolean', const: true };
    s.properties.severity = { type: 'string', enum: ['critical'] };
    s.properties.confidence = { type: 'integer', const: 100 };
  }),
  'temperature 1.5 (resample until valid)': mutate((r) => { r.temperature = 1.5; }),
  'max_tokens changed': mutate((r) => { r.max_tokens = 4000; }),
  'chat_template_kwargs extra key': mutate((r) => { r.chat_template_kwargs.chat_template = '{{ "valid" }}'; }),
  'extra top-level key logit_bias': mutate((r) => { r.logit_bias = { 1234: 100 }; }),
  'missing response_format': mutate((r) => { delete r.response_format; }),
  'extra message field': mutate((r) => { r.messages[2].name = 'x'; }),
  'duplicate top-level key': honest.replace('"temperature":0', '"temperature":1.5,"temperature":0'),
  'duplicate nested key': honest.replace('"type":"json_schema"', '"type":"text","type":"json_schema"'),
};

for (const [name, body] of Object.entries(TAMPERED)) {
  test(`params tampered: ${name}`, () => {
    assert.notEqual(body, honest);
    assert.deepEqual(checkRequestAgainstProgram(body, program, DEMO_HUNTER), { ok: false, reason: 'params tampered' });
  });
}

test('reason order: prompt -> model -> params -> code', () => {
  const badParams = JSON.parse(TAMPERED['temperature 1.5 (resample until valid)']);
  const withModel = JSON.stringify({ ...badParams, model: 'openai/gpt-oss-120b' });
  assert.equal(checkRequestAgainstProgram(withModel, program, DEMO_HUNTER).reason, 'model mismatch');
  const fake = JSON.parse(fixture('fakecode').request_body);
  fake.temperature = 1.5;
  assert.equal(checkRequestAgainstProgram(JSON.stringify(fake), program, DEMO_HUNTER).reason, 'params tampered');
  // a duplicated model key is a parse failure (the contract's serde struct rejects it)
  const dupModel = honest.replace('"model":', '"model":"x","model":');
  assert.equal(checkRequestAgainstProgram(dupModel, program, DEMO_HUNTER).reason, 'system prompt tampered');
});

test('canonicalJson: sorted keys (utf8 byte order), compact, standard escapes', () => {
  assert.equal(typeof judge.canonicalJson, 'function', 'canonicalJson is exported');
  assert.equal(judge.canonicalJson({ b: 1, a: [true, null, { d: 'x', c: 0 }] }), '{"a":[true,null,{"c":0,"d":"x"}],"b":1}');
  assert.equal(judge.canonicalJson({ s: 'q"\\\n\u0001é' }), '{"s":"q\\"\\\\\\n\\u0001é"}');
  // UTF-16 order would put U+FF5E before U+1F600; utf8 byte order (Rust String Ord) does not.
  assert.equal(judge.canonicalJson({ '\u{1F600}': 1, '～': 2 }), '{"～":2,"\u{1F600}":1}');
});

test('paramsHash: demo request == default canonical params == pinned hex', () => {
  assert.equal(typeof judge.paramsHash, 'function', 'paramsHash is exported');
  assert.equal(judge.paramsHash(), DEMO_PARAMS_HASH);
  for (const f of ['sqli', 'sqli.ecdsa', 'idor', 'bogus', 'injection', 'fakecode']) {
    assert.equal(judge.paramsHash(JSON.parse(fixture(f).request_body)), DEMO_PARAMS_HASH, f);
  }
});

test('v2 program (no params_hash): params step skipped, as the v2 contract does', () => {
  const { params_hash, ...v2 } = program;
  assert.equal(checkRequestAgainstProgram(TAMPERED['temperature 1.5 (resample until valid)'], v2, DEMO_HUNTER).ok, true);
});
