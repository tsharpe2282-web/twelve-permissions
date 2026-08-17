import { test } from 'node:test';
import assert from 'node:assert/strict';
import { consumeRateLimit } from '../src/ratelimit.js';

// Minimal in-memory stand-in for Workers KV: only get/put, same async shape.
// Mirrors hosting/test/ratelimit.test.js — this module is a reuse of that
// one (same semantics), so the same coverage applies here.
const fakeKV = () => {
  const m = new Map();
  return {
    store: m,
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async put(k, v) { m.set(k, String(v)); }
  };
};

const LIMIT = { limit: 3, windowSec: 3600 };
const NOW = 1_760_000_000;

test('allows the first request', async () => {
  const r = await consumeRateLimit(fakeKV(), 'ip:1.2.3.4', LIMIT, NOW);
  assert.equal(r.ok, true);
  assert.equal(r.count, 1);
});

test('allows requests up to the limit', async () => {
  const kv = fakeKV();
  for (let i = 1; i <= 3; i++) {
    const r = await consumeRateLimit(kv, 'ip:1.2.3.4', LIMIT, NOW);
    assert.equal(r.ok, true, `request ${i} should be allowed`);
  }
});

test('rejects the request after the limit is spent', async () => {
  const kv = fakeKV();
  for (let i = 0; i < 3; i++) await consumeRateLimit(kv, 'ip:1.2.3.4', LIMIT, NOW);
  const r = await consumeRateLimit(kv, 'ip:1.2.3.4', LIMIT, NOW);
  assert.equal(r.ok, false);
  assert.equal(r.count, 4);
});

test('a new time window restores the allowance', async () => {
  const kv = fakeKV();
  for (let i = 0; i < 4; i++) await consumeRateLimit(kv, 'ip:1.2.3.4', LIMIT, NOW);
  const later = await consumeRateLimit(kv, 'ip:1.2.3.4', LIMIT, NOW + 3600);
  assert.equal(later.ok, true, 'the next window must not inherit the old count');
});

test('separate buckets do not share an allowance', async () => {
  const kv = fakeKV();
  for (let i = 0; i < 4; i++) await consumeRateLimit(kv, 'ip:1.1.1.1', LIMIT, NOW);
  const other = await consumeRateLimit(kv, 'ip:9.9.9.9', LIMIT, NOW);
  assert.equal(other.ok, true, 'one abuser must not lock out everyone else');
});

test('a KV failure does not deny a legitimate caller', async () => {
  const brokenKV = { async get() { throw new Error('kv down'); }, async put() {} };
  const r = await consumeRateLimit(brokenKV, 'ip:1.2.3.4', LIMIT, NOW);
  assert.equal(r.ok, true, 'fail open: losing the counter must not block a legitimate probe');
});
