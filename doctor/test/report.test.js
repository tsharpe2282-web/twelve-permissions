import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildReport, BUILT_BY } from '../src/report.js';
import { RULES } from '../src/rules.js';

const chal = (over = {}) => ({
  ok: true, unreachableReason: null, httpStatus: 402, truncated: false,
  parseError: null, headers: { 'cache-control': 'no-store' },
  bodyText: '{}',
  body: { x402Version: 1, accepts: [{
    scheme: 'exact', network: 'base', maxAmountRequired: '9000000',
    asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    payTo: '0xe2f44B7F4B383C8aA7613401F5E855646C9457fa',
    maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' } }] },
  ...over
});

test('a clean challenge reports healthy', () => {
  const r = buildReport('https://x.test/p', chal());
  assert.equal(r.status, 'healthy');
  assert.deepEqual(r.findings, []);
});

test('an unreachable probe is never healthy', () => {
  const r = buildReport('https://x.test/p', {
    ok: false, unreachableReason: 'timeout', httpStatus: 0, headers: {},
    bodyText: '', body: null, parseError: null, truncated: false
  });
  assert.equal(r.status, 'unreachable');
  assert.equal(r.reason, 'timeout');
});

test('a 200 JSON endpoint that is not x402 reports not_x402', () => {
  const c = chal({ httpStatus: 200, body: { hello: 'world' } });
  const r = buildReport('https://x.test/p', c);
  assert.equal(r.status, 'not_x402');
});

// FINAL FIX PASS, IMPORTANT 5 — status is now severity-aware. A warn-only
// result is 'advisories', not 'defects_found': challenge-cacheable fires on
// the stock x402-express/x402-hono middleware and payto-not-checksummed fires
// on the very common all-lowercase payTo, so an ordinary correct endpoint was
// being labelled as having defects.
test('a warn-only result is advisories, not defects_found', () => {
  const c = chal(); c.headers = {};   // drops no-store -> challenge-cacheable (warn)
  const r = buildReport('https://x.test/p', c);
  assert.equal(r.status, 'advisories');
  // RE-REVIEW, FINDING E: `>= 15` was vacuous — 15 is the maximum, so the
  // assertion could only ever be satisfied by the one value it should pin.
  assert.equal(r.checksRun, RULES.length);
  assert.ok(r.findings.some(f => f.id === 'challenge-cacheable'));
  assert.ok(r.findings.every(f => f.severity !== 'error'));
});

test('an info-only result is advisories', () => {
  const c = chal();
  c.body.accepts[0].payTo = '0xe2f44b7f4b383c8aa7613401f5e855646c9457fa'; // lowercase: info
  const r = buildReport('https://x.test/p', c);
  assert.deepEqual(r.findings.map(f => f.id), ['payto-not-checksummed']);
  assert.equal(r.status, 'advisories');
});

test('a single error finding makes the whole report defects_found', () => {
  const c = chal();
  c.body.accepts[0].maxAmountRequired = 9; // error
  c.headers = {};                          // plus a warn, to prove severity wins over count
  const r = buildReport('https://x.test/p', c);
  assert.ok(r.findings.some(f => f.severity === 'error'));
  assert.equal(r.status, 'defects_found');
});

test('no findings at all is still healthy', () => {
  assert.equal(buildReport('https://x.test/p', chal()).status, 'healthy');
});

// RE-REVIEW, FINDING B — the end-to-end consequence of the severity change.
// An Avalanche seller doing everything right must not be handed a CAUTION
// light for a gap in this probe's network list.
//
// NOTE, flagged for the coordinator: Finding B asks for this to read
// 'healthy'. It reads 'advisories'. Downgrading the severity cannot produce
// 'healthy', because IMPORTANT 5 specified — and the re-review confirmed
// closed — that 'advisories' covers "the worst finding is warn OR INFO", and
// 'healthy' means no findings at all. Making an info-only result 'healthy'
// would require rewriting statusFor against that accepted contract and would
// contradict the 'an info-only result is advisories' test above. The
// substance of Finding B is delivered: warn (a caution light) becomes info
// (a note), which is the distinction the finding is actually about.
test('a working endpoint on a network this probe does not know draws only a note, not a caution', () => {
  const c = chal();
  c.body.accepts[0].network = 'avalanche';
  c.body.accepts[0].asset = '0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E';
  const r = buildReport('https://x.test/p', c);
  assert.deepEqual(r.findings.map(f => f.id), ['unknown-network-name']);
  assert.deepEqual(r.findings.map(f => f.severity), ['info']);
  assert.ok(!r.findings.some(f => f.severity === 'warn' || f.severity === 'error'));
  assert.equal(r.status, 'advisories');
});

// FINAL FIX PASS, IMPORTANT 4 — checksRun said 15 on the same object that
// said 10 body checks were skipped. Those cannot both be true.
test('checksRun reconciles with bodyChecksSkipped on a parse-error challenge', () => {
  const c = chal({ body: null, parseError: 'Unexpected token', truncated: false });
  const r = buildReport('https://x.test/p', c);
  // RE-REVIEW, FINDING E: this asserted `checksRun === RULES.length -
  // bodyChecksSkipped`, which is the source expression restated — the same
  // tautology criticised in the truncated-body test, and it would have passed
  // against any pair of numbers that happened to subtract correctly. Pinned to
  // literals: 16 rules, 11 of them body-scoped, so 5 actually ran. (Was 15/10/5
  // before payto-not-an-address; the new rule is body-scoped, so the skipped
  // count rose by one and the ran count is unchanged.)
  assert.equal(r.bodyChecksSkipped, 11);
  assert.equal(r.checksRun, 5);
  assert.equal(r.checksRun + r.bodyChecksSkipped, RULES.length);
});

test('checksRun is the full table when nothing was skipped', () => {
  const r = buildReport('https://x.test/p', chal());
  assert.equal(r.bodyChecksSkipped, 0);
  assert.equal(r.checksRun, RULES.length);
});

// FINAL FIX PASS, IMPORTANT 7 — probe computes blockedReason and finalUrl,
// and the report used to drop both on the floor.
test('an unreachable report surfaces the blockedReason probe computed', () => {
  const r = buildReport('https://x.test/p', {
    ok: false, unreachableReason: 'blocked_redirect', httpStatus: 0, headers: {},
    bodyText: '', body: null, parseError: null, truncated: false,
    finalUrl: null, blockedReason: 'malformed Location header'
  });
  assert.equal(r.status, 'unreachable');
  assert.equal(r.reason, 'blocked_redirect');
  assert.equal(r.blockedReason, 'malformed Location header');
});

test('an unreachable report with no blockedReason reports null, not undefined', () => {
  const r = buildReport('https://x.test/p', {
    ok: false, unreachableReason: 'timeout', httpStatus: 0, headers: {},
    bodyText: '', body: null, parseError: null, truncated: false, finalUrl: null
  });
  assert.equal(r.blockedReason, null);
});

test('a report surfaces the final URL the findings actually describe', () => {
  const c = chal();
  c.finalUrl = 'https://x.test/p/redirected';
  const r = buildReport('https://x.test/p', c);
  assert.equal(r.target, 'https://x.test/p');
  assert.equal(r.finalUrl, 'https://x.test/p/redirected');
});

// FINAL FIX PASS, MINOR — the not_x402 branch hardcoded bodyTruncated: false
// even when the probe had truncated the body.
test('a truncated non-x402 response does not claim the body was read in full', () => {
  const c = chal({ httpStatus: 200, body: null, truncated: true });
  const r = buildReport('https://x.test/p', c);
  assert.equal(r.status, 'not_x402');
  assert.equal(r.bodyTruncated, true);
});

test('every report carries the byline', () => {
  const r = buildReport('https://x.test/p', chal());
  assert.equal(r.built_by.url, BUILT_BY.url);
  assert.ok(r.built_by.name);
});

// --- Deviation from the task-8 brief, authorized by controller ruling 2026-08-17:
// a truncated or otherwise-unusable body silently skips every body-scoped rule
// (rules.js's bodyUnusable), which must be disclosed rather than left invisible.

test('a truncated body discloses skipped checks and suppresses body findings', () => {
  const c = chal({ truncated: true });
  // Would normally fire 'amount-not-atomic-string' if body rules ran.
  c.body.accepts[0].maxAmountRequired = 9000000;
  const r = buildReport('https://x.test/p', c);
  assert.equal(r.bodyTruncated, true);
  assert.ok(r.bodyChecksSkipped > 0);
  assert.equal(r.bodySkipReason, 'truncated');
  assert.ok(!r.findings.some(f => f.id === 'amount-not-atomic-string'));
  // FINAL FIX PASS, IMPORTANT 5: status is severity-aware now. The only rule
  // this challenge trips is oversized-body, a warn, so the report reads
  // 'advisories' rather than 'defects_found'.
  assert.deepEqual(r.findings.map(f => f.severity), ['warn']);
  assert.equal(r.status, 'advisories');
});

test('a full, usable body has no skipped-check disclosure', () => {
  const r = buildReport('https://x.test/p', chal());
  assert.equal(r.bodyTruncated, false);
  assert.equal(r.bodyChecksSkipped, 0);
  assert.equal(r.bodySkipReason, null);
});

test('a body unusable for a reason other than truncation still discloses skipped checks', () => {
  const c = chal({ httpStatus: 402, body: null, parseError: 'Unexpected token', truncated: false });
  const r = buildReport('https://x.test/p', c);
  assert.equal(r.bodyTruncated, false);
  assert.ok(r.bodyChecksSkipped > 0);
  assert.equal(r.bodySkipReason, 'parse_error');
});

test('a missing body with no parse error still discloses skipped checks', () => {
  const c = chal({ httpStatus: 402, body: undefined, parseError: null, truncated: false });
  const r = buildReport('https://x.test/p', c);
  assert.equal(r.bodyTruncated, false);
  assert.ok(r.bodyChecksSkipped > 0);
  assert.equal(r.bodySkipReason, 'no_body');
});

// --- Guard test, controller ruling round 2, 2026-08-17: report.js's disclosure
// must agree with what the rules engine actually skips, derived from the same
// source (rules.js's exported bodySkipReason), not a second hand-maintained copy.

test('reported bodyChecksSkipped matches the rules engine\'s actual body-rule count', () => {
  const bodyRuleIds = RULES.filter((r) => r.appliesTo === 'body').map((r) => r.id);

  // A body defective enough to trip every entry-based body rule at once (plus
  // a bad top-level x402Version), so that if these rules were NOT actually
  // skipped, at least one of their ids would show up as a finding below.
  // (accepts-empty is excluded on purpose: it fires only when there is no
  // entry to inspect, which is mutually exclusive with the rest.)
  const c = chal({
    truncated: true,
    body: {
      x402Version: 2, // would fire missing-x402-version
      accepts: [{
        scheme: 'exact',
        network: 'base-mainnet',              // would fire unknown-network-name
        maxAmountRequired: 9,                  // would fire amount-not-atomic-string
        asset: '0xWRONG',                      // would fire asset-network-mismatch
        payTo: '0xe2f44b7f4b383c8aa7613401f5e855646c9457fa', // would fire payto-not-checksummed
        outputSchema: null,                    // would fire output-schema-null
        extensions: { foo: 1 },                // would fire bazaar-ext-inside-accepts
        extra: {}                              // would fire missing-eip712-extra
        // maxTimeoutSeconds omitted -> would fire no-timeout-declared
      }]
    }
  });

  const r = buildReport('https://x.test/p', c);

  // The count report.js discloses must equal the actual number of body rules
  // in the live rule table — computed here independently, not by reaching
  // into report.js's internals.
  assert.equal(r.bodyChecksSkipped, bodyRuleIds.length);

  // And the skip must be real: none of those ids appear as findings, even
  // though this body is defective enough to trip every one of them.
  for (const id of bodyRuleIds) {
    assert.ok(!r.findings.some((f) => f.id === id), `expected ${id} to be skipped, not evaluated`);
  }
});
