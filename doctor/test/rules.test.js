import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RULES, runRules } from '../src/rules.js';

// Minimal well-formed challenge. Every bad fixture mutates ONE thing.
export const good = () => ({
  ok: true, unreachableReason: null, httpStatus: 402, truncated: false,
  parseError: null,
  headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  bodyText: '{}',
  body: {
    x402Version: 1,
    accepts: [{
      scheme: 'exact', network: 'base',
      maxAmountRequired: '9000000',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      payTo: '0xe2f44B7F4B383C8aA7613401F5E855646C9457fa',
      maxTimeoutSeconds: 300,
      extra: { name: 'USD Coin', version: '2' }
    }]
  }
});

test('every rule declares an id, severity, appliesTo, provenance and fix', () => {
  for (const r of RULES) {
    assert.ok(r.id, 'rule missing id');
    assert.ok(['error', 'warn', 'info'].includes(r.severity), `${r.id}: bad severity`);
    assert.ok(['envelope', 'body', 'headers'].includes(r.appliesTo),
      `${r.id}: appliesTo must be 'envelope', 'body' or 'headers'`);
    assert.ok(r.provenance, `${r.id}: missing provenance`);
    assert.ok(r.provenance === 'spec' || r.provenance.startsWith('observed'),
      `${r.id}: provenance must be 'spec' or start with 'observed'`);
    assert.ok(r.fix && r.fix.trim() !== '', `${r.id}: missing fix text`);
  }
});

test('a well-formed challenge produces no findings', () => {
  assert.deepEqual(runRules(good()), []);
});

const ids = (f) => f.map(x => x.id).sort();

test('non-402 status fires no-402', () => {
  const c = good(); c.httpStatus = 200;
  assert.deepEqual(ids(runRules(c)), ['no-402']);
});

test('unparseable body fires body-not-json and no body rules', () => {
  const c = good();
  c.body = null; c.parseError = 'Unexpected token <'; c.bodyText = '<html>';
  assert.deepEqual(ids(runRules(c)), ['body-not-json']);
});

test('truncated body fires oversized-body and no body rules', () => {
  const c = good(); c.truncated = true; c.body = null;
  assert.deepEqual(ids(runRules(c)), ['oversized-body']);
});

test('missing x402Version fires missing-x402-version', () => {
  const c = good(); delete c.body.x402Version;
  assert.deepEqual(ids(runRules(c)), ['missing-x402-version']);
});

test('empty accepts fires accepts-empty', () => {
  const c = good(); c.body.accepts = [];
  assert.deepEqual(ids(runRules(c)), ['accepts-empty']);
});

test('accepts missing entirely fires accepts-empty only', () => {
  const c = good(); delete c.body.accepts;
  assert.deepEqual(ids(runRules(c)), ['accepts-empty']);
});

test('outputSchema null fires output-schema-null', () => {
  const c = good(); c.body.accepts[0].outputSchema = null;
  assert.deepEqual(ids(runRules(c)), ['output-schema-null']);
});

test('numeric maxAmountRequired fires amount-not-atomic-string', () => {
  const c = good(); c.body.accepts[0].maxAmountRequired = 9;
  assert.deepEqual(ids(runRules(c)), ['amount-not-atomic-string']);
});

test('decimal string maxAmountRequired fires amount-not-atomic-string', () => {
  const c = good(); c.body.accepts[0].maxAmountRequired = '9.00';
  assert.deepEqual(ids(runRules(c)), ['amount-not-atomic-string']);
});

test('wrong USDC contract for the network fires asset-network-mismatch', () => {
  const c = good();
  c.body.accepts[0].asset = '0x036CbD53842c5426634e7929541eC2318f3dCF7e'; // sepolia USDC on base
  assert.deepEqual(ids(runRules(c)), ['asset-network-mismatch']);
});

test('missing extra on scheme exact fires missing-eip712-extra', () => {
  const c = good(); delete c.body.accepts[0].extra;
  assert.deepEqual(ids(runRules(c)), ['missing-eip712-extra']);
});

// FINAL FIX PASS, CRITICAL 1 — this test previously asserted that an
// unrecognised network name ALSO fired asset-network-mismatch. That was the
// bug, encoded as an expectation: we do not know which USDC contract belongs
// to a network we do not recognise, so we cannot know the asset is wrong.
// The unknown network is already reported once, by unknown-network-name.
test('base-mainnet fires unknown-network-name only — we cannot judge the asset for a network we do not know', () => {
  const c = good(); c.body.accepts[0].network = 'base-mainnet';
  assert.deepEqual(ids(runRules(c)), ['unknown-network-name']);
});

// x402's network set is much larger than the two networks whose USDC contract
// this probe knows: avalanche, avalanche-fuji, polygon, polygon-amoy, sei,
// iotex, solana, solana-devnet. A healthy seller on any of them must not be
// told it has a settlement-breaking asset error.
test('a healthy Avalanche entry produces no asset-network-mismatch', () => {
  const c = good();
  c.body.accepts[0].network = 'avalanche';
  c.body.accepts[0].asset = '0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E'; // Avalanche USDC
  const found = ids(runRules(c));
  assert.ok(!found.includes('asset-network-mismatch'), `unexpected findings: ${found}`);
  assert.deepEqual(found, ['unknown-network-name']);
});

test('a healthy Solana-style entry fires neither EVM-only rule nor asset-network-mismatch', () => {
  const c = good();
  c.body.accepts[0].network = 'solana';
  c.body.accepts[0].asset = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'; // Solana USDC mint
  c.body.accepts[0].payTo = '9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM'; // base58, not an EVM address
  delete c.body.accepts[0].extra; // non-EVM chains have no EIP-712 domain
  const found = ids(runRules(c));
  assert.ok(!found.includes('missing-eip712-extra'), 'EIP-712 is EVM-only');
  assert.ok(!found.includes('payto-not-checksummed'), 'EIP-55 casing is EVM-only');
  assert.ok(!found.includes('asset-network-mismatch'), 'we do not know solana USDC');
  assert.deepEqual(found, ['unknown-network-name']);
});

// RE-REVIEW ROUND 2 — the 16th rule. Closing the residual flagged after
// FINDING A: widening the gate stopped a garbage payTo on a known EVM network
// being SILENT, but it was still reported as `info: payto-not-checksummed`,
// titled "payTo is not a checksummed address". A string that is not an address
// at all is not an address missing its checksum casing, and the consequence is
// not cosmetic: payment cannot be sent anywhere. Under-reporting a
// settlement-breaking defect as a styling note is the same quiet failure this
// branch has been closing throughout.
test('a garbage payTo on a known EVM network is an error, not a checksum note', () => {
  const c = good(); c.body.accepts[0].payTo = 'not-an-address';
  const found = ids(runRules(c));
  assert.deepEqual(found, ['payto-not-an-address']);
  const f = runRules(c).find((x) => x.id === 'payto-not-an-address');
  assert.equal(f.severity, 'error');
  // One defect, one finding: a non-address must not ALSO be reported as an
  // address that merely lacks EIP-55 casing.
  assert.ok(!found.includes('payto-not-checksummed'));
});

test('a payTo of the wrong length on a known EVM network fires payto-not-an-address', () => {
  const c = good();
  c.body.accepts[0].payTo = '0xe2f44b7f4b383c8aa7613401f5e855646c9457f'; // 39 hex digits
  assert.deepEqual(ids(runRules(c)), ['payto-not-an-address']);
});

test('an absent payTo on a known EVM network fires payto-not-an-address', () => {
  const c = good(); delete c.body.accepts[0].payTo;
  let found;
  assert.doesNotThrow(() => { found = ids(runRules(c)); });
  assert.deepEqual(found, ['payto-not-an-address']);
});

test('a non-string payTo on a known EVM network fires payto-not-an-address', () => {
  for (const bad of [42, null, {}, ['0xabc']]) {
    const c = good(); c.body.accepts[0].payTo = bad;
    let found;
    assert.doesNotThrow(() => { found = ids(runRules(c)); }, `threw on ${JSON.stringify(bad)}`);
    assert.deepEqual(found, ['payto-not-an-address'], `for payTo = ${JSON.stringify(bad)}`);
  }
});

test('a valid but lowercase payTo still fires only payto-not-checksummed', () => {
  const c = good();
  c.body.accepts[0].payTo = '0xe2f44b7f4b383c8aa7613401f5e855646c9457fa';
  const found = ids(runRules(c));
  assert.deepEqual(found, ['payto-not-checksummed']);
  assert.ok(!found.includes('payto-not-an-address'), 'a real address is an address');
});

test('payto-not-an-address does not judge address formats it cannot know', () => {
  // Non-EVM / unrecognised network: we hold no address format for it, so the
  // rule must stay silent rather than call a valid base58 address malformed.
  const c = good();
  c.body.accepts[0].network = 'solana';
  c.body.accepts[0].payTo = '9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM';
  c.body.accepts[0].asset = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
  delete c.body.accepts[0].extra;
  assert.ok(!ids(runRules(c)).includes('payto-not-an-address'));
});

test('the payto-not-an-address evidence reports what payTo actually was', () => {
  const c = good(); c.body.accepts[0].payTo = 'wallet-tbd';
  const f = runRules(c).find((x) => x.id === 'payto-not-an-address');
  assert.match(f.evidence, /wallet-tbd/);
});

test('a pathologically long payTo is truncated in the evidence', () => {
  const c = good(); c.body.accepts[0].payTo = 'z'.repeat(5000);
  const f = runRules(c).find((x) => x.id === 'payto-not-an-address');
  assert.ok(f.evidence.length < 300, `evidence was ${f.evidence.length} chars`);
});

// RE-REVIEW, FINDING A — the first cut of the EVM gate keyed solely on the
// SHAPE of payTo, which meant a malformed or absent payTo made an entry
// "not EVM-shaped" and silenced both EVM rules. Nothing else in the table
// inspects payTo, so a genuinely broken Base entry could come back healthy:
// a false positive traded for a false negative, which is the same failure
// with the volume turned down.
// These two are the anti-SILENCE guards for FINDING A, kept deliberately
// separate from the payto-not-an-address tests above: those pin which rule
// speaks, these pin only that SOMETHING does. Updated for the 16th rule — the
// finding they assert is now the error rather than the checksum note, which is
// a strictly better answer to the same question.
test('a Base entry with a malformed payTo is still judged, not silently exempted', () => {
  const c = good();
  c.body.accepts[0].payTo = '0xe2f44b7f4b383c8aa7613401f5e855646c9457f'; // 39 hex digits, one short
  const found = ids(runRules(c));
  assert.ok(found.length > 0, 'a malformed payTo on a known EVM network must not return silence');
  assert.ok(found.includes('payto-not-an-address'), `expected the payTo to be flagged, got: ${found}`);
});

test('a Base entry with payTo absent entirely does not crash and is still judged', () => {
  const c = good();
  delete c.body.accepts[0].payTo;
  let found;
  assert.doesNotThrow(() => { found = ids(runRules(c)); });
  assert.ok(found.includes('payto-not-an-address'), `expected a finding, got: ${found}`);
});

test('a Base entry missing its EIP-712 extra is judged even when payTo is malformed', () => {
  const c = good();
  c.body.accepts[0].payTo = 'not-an-address';
  delete c.body.accepts[0].extra;
  const found = ids(runRules(c));
  assert.ok(found.includes('missing-eip712-extra'),
    `the network is base, so EIP-712 applies regardless of the payTo typo; got: ${found}`);
});

// FINAL FIX PASS, CRITICAL 2 — the "exact" scheme is EIP-3009 over any
// conforming ERC-20, so a Base endpoint priced in EURC is legitimate. An
// asset we do not recognise is an observation, not a settlement failure.
test('asset-network-mismatch is a warn, and reads as an observation not a failure', () => {
  const r = RULES.find((x) => x.id === 'asset-network-mismatch');
  assert.equal(r.severity, 'warn');
  assert.doesNotMatch(r.why, /cannot settle/i);
});

// FINAL FIX PASS — with CRITICAL 1 fixed, unknown-network-name is now the ONLY
// thing said about a healthy Avalanche or Solana endpoint. Its old text ("a
// facilitator will not route it", "Use one of: base, base-sepolia") would
// therefore instruct a working non-Base seller to break itself. The rule may
// report that it does not recognise the name; it may not claim the name is
// wrong, because it does not know that.
test('unknown-network-name reports non-recognition without asserting the network is invalid', () => {
  const r = RULES.find((x) => x.id === 'unknown-network-name');
  // RE-REVIEW, FINDING B: a `warn` here contradicts the rule's own text. The
  // finding is a fact about OUR list, not about THEIR service, so it must not
  // put a caution light on a working endpoint.
  assert.equal(r.severity, 'info');
  const text = `${r.why} ${r.fix}`;
  assert.doesNotMatch(text, /will not route/i);
  assert.doesNotMatch(r.fix, /^Use one of/i);
  // It must acknowledge that valid x402 networks exist outside its short list.
  assert.match(text, /avalanche|solana|polygon/i);
});

test('lowercase payTo fires payto-not-checksummed', () => {
  const c = good(); c.body.accepts[0].payTo = '0xe2f44b7f4b383c8aa7613401f5e855646c9457fa';
  assert.deepEqual(ids(runRules(c)), ['payto-not-checksummed']);
});

test('missing maxTimeoutSeconds fires no-timeout-declared', () => {
  const c = good(); delete c.body.accepts[0].maxTimeoutSeconds;
  assert.deepEqual(ids(runRules(c)), ['no-timeout-declared']);
});

test('cacheable challenge fires challenge-cacheable', () => {
  const c = good(); c.headers['cache-control'] = 'public, max-age=300';
  assert.deepEqual(ids(runRules(c)), ['challenge-cacheable']);
});

test('absent cache-control fires challenge-cacheable', () => {
  const c = good(); delete c.headers['cache-control'];
  assert.deepEqual(ids(runRules(c)), ['challenge-cacheable']);
});

test('bazaar extension inside an accepts entry fires bazaar-ext-inside-accepts', () => {
  const c = good(); c.body.accepts[0].extensions = { bazaar: { info: {} } };
  assert.deepEqual(ids(runRules(c)), ['bazaar-ext-inside-accepts']);
});

// FINAL FIX PASS, IMPORTANT 6 — the headers a browser x402 client reads
// (X-PAYMENT-RESPONSE) ride on the SETTLEMENT 200, which this probe never
// requests. The rule may raise the possibility; it may not claim a defect on
// a response it did not fetch.
test('cors-headers-not-exposed is informational and does not claim a defect it cannot observe', () => {
  const r = RULES.find((x) => x.id === 'cors-headers-not-exposed');
  assert.equal(r.severity, 'info');
  assert.match(r.why, /settlement/i);
  assert.match(r.why, /cannot confirm|does not|only the 402/i);
});

test('the cors evidence string states what was observed, not that something is broken', () => {
  const c = good();
  c.headers['access-control-allow-origin'] = '*';
  const f = runRules(c).find((x) => x.id === 'cors-headers-not-exposed');
  assert.ok(f, 'rule should still fire so the reader hears about it');
  assert.doesNotMatch(f.evidence, /empty|missing|not exposed/i);
  assert.match(f.evidence, /access-control-expose-headers/i);
});

test('the table has sixteen rules and no duplicate ids', () => {
  // 15 -> 16 with payto-not-an-address (re-review round 2). Deliberate count
  // change; every other surface derives its count from RULES.length.
  assert.equal(RULES.length, 16);
  assert.equal(new Set(RULES.map(r => r.id)).size, 16);
});

test('malformed challenges never throw', () => {
  const nasty = [
    { ok: true, httpStatus: 402, headers: {}, body: null, parseError: 'x', truncated: false },
    { ok: true, httpStatus: 402, headers: {}, body: {}, parseError: null, truncated: false },
    { ok: true, httpStatus: 402, headers: {}, body: { accepts: null }, parseError: null, truncated: false },
    { ok: true, httpStatus: 402, headers: {}, body: { accepts: [{}] }, parseError: null, truncated: false },
    { ok: true, httpStatus: 402, headers: {}, body: { accepts: 'nope' }, parseError: null, truncated: false }
  ];
  for (const c of nasty) assert.doesNotThrow(() => runRules(c));
});
