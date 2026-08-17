import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';
import { RULES } from '../src/rules.js';
import { TOOLS } from '../src/mcp.js';
import { STATUS_VALUES } from '../src/report.js';

const fakeKV = () => {
  const m = new Map();
  return { async get(k) { return m.has(k) ? m.get(k) : null; }, async put(k, v) { m.set(k, String(v)); } };
};

const envWith = (kv) => ({ RATE_LIMIT_KV: kv });

const req = (path, { method = 'GET', body, ip, headers = {} } = {}) => new Request(`https://doctor.test${path}`, {
  method,
  headers: { 'Content-Type': 'application/json', ...(ip ? { 'CF-Connecting-IP': ip } : {}), ...headers },
  body: body !== undefined ? JSON.stringify(body) : undefined
});

const cleanX402Body = {
  x402Version: 1,
  accepts: [{
    scheme: 'exact', network: 'base', maxAmountRequired: '9000000',
    asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    payTo: '0xe2f44B7F4B383C8aA7613401F5E855646C9457fa',
    maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' }
  }]
};

async function withStubbedFetch(fn) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify(cleanX402Body), {
    status: 402, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }
  });
  try { return await fn(); } finally { globalThis.fetch = original; }
}

// --- Routing -----------------------------------------------------------

test('OPTIONS gets a CORS preflight response', async () => {
  const res = await worker.fetch(req('/probe', { method: 'OPTIONS' }), envWith(fakeKV()));
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), '*');
});

test('GET / serves the docs page with utf-8 charset and every rule listed', async () => {
  const res = await worker.fetch(req('/'), envWith(fakeKV()));
  assert.equal(res.status, 200);
  assert.match(res.headers.get('Content-Type'), /text\/html.*charset=utf-8/);
  const html = await res.text();
  assert.match(html, /<meta charset="utf-8">/);
  assert.match(html, /x402 Doctor/);
  for (const r of RULES) assert.match(html, new RegExp(r.id), `missing rule id ${r.id}`);
});

// FINAL FIX PASS, IMPORTANT 5 — 'advisories' is new vocabulary in the output,
// so the docs page has to define it, and must stay in step with the statuses
// report.js can actually emit.
test('the docs page explains every status value the report can emit', async () => {
  const res = await worker.fetch(req('/'), envWith(fakeKV()));
  const html = await res.text();
  for (const s of STATUS_VALUES) assert.match(html, new RegExp(s), `docs page never mentions status ${s}`);
});

// RE-REVIEW, FINDING C — the hero promised "exactly what is wrong with the 402
// challenge" while the MCP description had already been softened to "report
// what it observes". The tool checks a named, finite rule set; it does not know
// everything that is wrong with an endpoint, and must not imply that it does.
test('the docs page does not promise to find everything wrong with an endpoint', async () => {
  const res = await worker.fetch(req('/'), envWith(fakeKV()));
  const html = await res.text();
  assert.doesNotMatch(html, /exactly what is wrong/i);
  assert.match(html, /observ/i, 'the page should describe what it observed, not what is wrong');
});

test('unknown path is a 404 with routing guidance', async () => {
  const res = await worker.fetch(req('/nope'), envWith(fakeKV()));
  assert.equal(res.status, 404);
});

test('POST /probe with a non-JSON body is a 400', async () => {
  const res = await worker.fetch(new Request('https://doctor.test/probe', {
    method: 'POST', headers: { 'CF-Connecting-IP': '1.1.1.1' }, body: 'not json'
  }), envWith(fakeKV()));
  assert.equal(res.status, 400);
});

test('POST /probe with a private target is refused without touching the network', async () => {
  const originalFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => { called = true; throw new Error('must not be called'); };
  try {
    const res = await worker.fetch(req('/probe', { method: 'POST', ip: '1.1.1.1', body: { url: 'http://127.0.0.1/x' } }), envWith(fakeKV()));
    assert.equal(res.status, 400);
    assert.equal(called, false);
  } finally { globalThis.fetch = originalFetch; }
});

test('POST /probe on a clean target reports healthy', async () => {
  await withStubbedFetch(async () => {
    const res = await worker.fetch(req('/probe', { method: 'POST', ip: '2.2.2.2', body: { url: 'https://example.test/x' } }), envWith(fakeKV()));
    assert.equal(res.status, 200);
    const out = await res.json();
    assert.equal(out.status, 'healthy');
  });
});

// --- MCP -----------------------------------------------------------------

test('mcp initialize identifies the server', async () => {
  const res = await worker.fetch(req('/mcp', { method: 'POST', ip: '3.3.3.3', body: { jsonrpc: '2.0', id: 1, method: 'initialize' } }), envWith(fakeKV()));
  const out = await res.json();
  assert.equal(out.result.serverInfo.name, 'x402-doctor');
});

test('mcp tools/list returns the exported TOOLS table', async () => {
  const res = await worker.fetch(req('/mcp', { method: 'POST', ip: '3.3.3.3', body: { jsonrpc: '2.0', id: 2, method: 'tools/list' } }), envWith(fakeKV()));
  const out = await res.json();
  assert.deepEqual(out.result.tools, TOOLS);
});

test('mcp tools/call list_checks is not gated by the probe rate limit', async () => {
  const kv = fakeKV();
  for (let i = 0; i < 40; i++) {
    const res = await worker.fetch(req('/mcp', {
      method: 'POST', ip: '4.4.4.4',
      body: { jsonrpc: '2.0', id: i, method: 'tools/call', params: { name: 'list_checks', arguments: {} } }
    }), envWith(kv));
    assert.equal(res.status, 200, `call ${i} should not be rate limited`);
  }
});

test('mcp tools/call probe_x402_endpoint on a clean target reports healthy', async () => {
  await withStubbedFetch(async () => {
    const res = await worker.fetch(req('/mcp', {
      method: 'POST', ip: '5.5.5.5',
      body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'probe_x402_endpoint', arguments: { url: 'https://example.test/x' } } }
    }), envWith(fakeKV()));
    const out = await res.json();
    const report = JSON.parse(out.result.content[0].text);
    assert.equal(report.status, 'healthy');
  });
});

test('mcp notifications/initialized gets a bare 204', async () => {
  const res = await worker.fetch(req('/mcp', { method: 'POST', ip: '3.3.3.3', body: { jsonrpc: '2.0', method: 'notifications/initialized' } }), envWith(fakeKV()));
  assert.equal(res.status, 204);
});

// FINAL FIX PASS, MINOR — request.json() on the literal body `null` parses
// fine and yields null, so `rpc.method` threw and the Worker 500'd. /probe
// already guarded this with ?.; /mcp did not.
test('POST /mcp with a JSON null body is a clean 400, not a 500', async () => {
  const res = await worker.fetch(new Request('https://doctor.test/mcp', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '3.3.3.3' },
    body: 'null'
  }), envWith(fakeKV()));
  assert.notEqual(res.status, 500);
  assert.equal(res.status, 400);
});

test('POST /mcp with a JSON body that is not an object does not throw', async () => {
  for (const raw of ['null', '"a string"', '42', '[]']) {
    const res = await worker.fetch(new Request('https://doctor.test/mcp', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '3.3.3.3' },
      body: raw
    }), envWith(fakeKV()));
    assert.notEqual(res.status, 500, `body ${raw} should not 500`);
  }
});

test('mcp unknown method is a JSON-RPC method-not-found error', async () => {
  const res = await worker.fetch(req('/mcp', { method: 'POST', ip: '3.3.3.3', body: { jsonrpc: '2.0', id: 9, method: 'not/a/method' } }), envWith(fakeKV()));
  const out = await res.json();
  assert.equal(out.error.code, -32601);
});

// --- Abuse control (per-caller and global rate limiting) -----------------

test('POST /probe: requests up to the per-IP limit pass, the next one 429s with Retry-After', async () => {
  const kv = fakeKV();
  const ip = '6.6.6.6';
  for (let i = 0; i < 20; i++) {
    const res = await worker.fetch(req('/probe', { method: 'POST', ip, body: { url: 'http://127.0.0.1/x' } }), envWith(kv));
    assert.equal(res.status, 400, `request ${i} should pass the rate gate (rejected only by target validation)`);
  }
  const blocked = await worker.fetch(req('/probe', { method: 'POST', ip, body: { url: 'http://127.0.0.1/x' } }), envWith(kv));
  assert.equal(blocked.status, 429);
  assert.ok(blocked.headers.get('Retry-After'));
  const body = await blocked.json();
  assert.match(body.error, /rate limit/i);
});

test('POST /probe: a global ceiling applies even across many distinct IPs', async () => {
  const kv = fakeKV();
  for (let i = 0; i < 300; i++) {
    const res = await worker.fetch(req('/probe', { method: 'POST', ip: `distinct-${i}`, body: { url: 'http://127.0.0.1/x' } }), envWith(kv));
    assert.equal(res.status, 400, `request ${i} should pass the global gate`);
  }
  const blocked = await worker.fetch(req('/probe', { method: 'POST', ip: 'distinct-300', body: { url: 'http://127.0.0.1/x' } }), envWith(kv));
  assert.equal(blocked.status, 429, 'the 301st distinct caller should trip the global ceiling');
});

test('mcp probe_x402_endpoint shares the same rate gate as POST /probe', async () => {
  const kv = fakeKV();
  const ip = '7.7.7.7';
  for (let i = 0; i < 20; i++) {
    const res = await worker.fetch(req('/mcp', {
      method: 'POST', ip,
      body: { jsonrpc: '2.0', id: i, method: 'tools/call', params: { name: 'probe_x402_endpoint', arguments: { url: 'http://127.0.0.1/x' } } }
    }), envWith(kv));
    assert.equal(res.status, 200, `call ${i} should pass the rate gate`);
  }
  const blocked = await worker.fetch(req('/mcp', {
    method: 'POST', ip,
    body: { jsonrpc: '2.0', id: 99, method: 'tools/call', params: { name: 'probe_x402_endpoint', arguments: { url: 'http://127.0.0.1/x' } } }
  }), envWith(kv));
  assert.equal(blocked.status, 429);
  assert.ok(blocked.headers.get('Retry-After'));
});

test('a KV that always throws fails OPEN, not closed, for a legitimate caller', async () => {
  const brokenKV = { async get() { throw new Error('kv down'); }, async put() { throw new Error('kv down'); } };
  const ip = '8.8.8.8';
  for (let i = 0; i < 25; i++) {
    const res = await worker.fetch(req('/probe', { method: 'POST', ip, body: { url: 'http://127.0.0.1/x' } }), envWith(brokenKV));
    assert.equal(res.status, 400, `request ${i} must never be blocked by a broken rate-limit store`);
  }
});

test('no KV binding configured (e.g. local dry-run) also fails open', async () => {
  const res = await worker.fetch(req('/probe', { method: 'POST', ip: '9.9.9.9', body: { url: 'http://127.0.0.1/x' } }), {});
  assert.equal(res.status, 400);
});
