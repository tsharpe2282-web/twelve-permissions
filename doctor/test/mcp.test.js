import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { TOOLS, callTool } from '../src/mcp.js';
import { RULES } from '../src/rules.js';

const parse = (result) => JSON.parse(result.content[0].text);

test('TOOLS exposes exactly the three named tools', () => {
  assert.deepEqual(TOOLS.map((t) => t.name),
    ['probe_x402_endpoint', 'explain_defect', 'list_checks']);
});

test('each tool declares an inputSchema with additionalProperties: false', () => {
  for (const t of TOOLS) assert.equal(t.inputSchema.additionalProperties, false, t.name);
});

// FINAL FIX PASS, MINOR — the description hardcoded "against 15 rules", which
// silently becomes a lie the moment a rule is added or removed.
test('the probe tool description states the live rule count, not a hardcoded one', async () => {
  const t = TOOLS.find((x) => x.name === 'probe_x402_endpoint');
  const claimed = /against (\d+) rules/.exec(t.description);
  assert.ok(claimed, 'description should say how many rules it checks against');
  assert.equal(Number(claimed[1]), RULES.length);

  // The value above matching today proves nothing on its own — a hardcoded
  // literal would also match while RULES.length happens to equal it. Assert
  // the source carries no baked-in count, so adding a rule cannot silently
  // turn this description into a false claim.
  const src = await readFile(new URL('../src/mcp.js', import.meta.url), 'utf8');
  assert.doesNotMatch(src, /against \d+ rules/,
    'the rule count must be interpolated from RULES.length, not written as a literal');
});

test('list_checks returns every rule, publicly shaped (no check function leaked)', async () => {
  const out = parse(await callTool('list_checks', {}));
  assert.equal(out.count, RULES.length);
  assert.equal(out.checks.length, RULES.length);
  for (const c of out.checks) {
    assert.equal(c.check, undefined, 'the check() implementation must not be exposed');
    assert.ok(c.id && c.severity && c.title && c.why && c.fix && c.provenance);
  }
  assert.equal(out.built_by.url, 'https://twelvepermissions.com');
});

test('explain_defect returns the full public shape of a known rule', async () => {
  const out = parse(await callTool('explain_defect', { id: 'no-402' }));
  assert.equal(out.id, 'no-402');
  assert.ok(out.why && out.fix && out.provenance);
});

test('explain_defect on an unknown id reports the known ids instead of throwing', async () => {
  const out = parse(await callTool('explain_defect', { id: 'not-a-real-rule' }));
  assert.match(out.error, /not-a-real-rule/);
  assert.equal(out.known_ids.length, RULES.length);
});

test('probe_x402_endpoint refuses a private target without making a network call', async () => {
  const originalFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => { called = true; throw new Error('must not be called'); };
  try {
    const out = parse(await callTool('probe_x402_endpoint', { url: 'http://127.0.0.1/x' }));
    assert.match(out.error, /private|loopback/i);
    assert.equal(called, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('probe_x402_endpoint on a clean target returns a healthy report', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({
    x402Version: 1,
    accepts: [{
      scheme: 'exact', network: 'base', maxAmountRequired: '9000000',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      payTo: '0xe2f44B7F4B383C8aA7613401F5E855646C9457fa',
      maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' }
    }]
  }), { status: 402, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  try {
    const out = parse(await callTool('probe_x402_endpoint', { url: 'https://example.test/x' }));
    assert.equal(out.status, 'healthy');
    assert.equal(out.checksRun, RULES.length);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('an unknown tool name reports an error instead of throwing', async () => {
  const out = parse(await callTool('not_a_tool', {}));
  assert.match(out.error, /not_a_tool/);
});
