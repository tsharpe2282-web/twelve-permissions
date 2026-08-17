// THE RULE TABLE — the product.
//
// Every rule is a pure function of a Challenge. No I/O, no clock, no throwing.
// `provenance` is mandatory and separates "the spec requires this" from
// "we watched a real facilitator reject this", so no finding has to be taken
// on trust.
export const RULES = [];

// Body rules are skipped whenever the envelope is unusable. Reporting them as
// passing would be a lie: we did not check, which is not the same as fine.
//
// Exported as the single source of truth for *why* the body is unusable —
// report.js discloses this reason to the reader instead of maintaining a
// second copy of these conditions that could silently drift out of sync with
// the gate actually enforced below.
export function bodySkipReason(c) {
  if (c.parseError !== null) return 'parse_error';
  if (c.truncated) return 'truncated';
  if (!c.body) return 'no_body';
  return null;
}

const bodyUnusable = (c) => bodySkipReason(c) !== null;

RULES.push({
  id: 'no-402', severity: 'error', appliesTo: 'envelope', provenance: 'spec',
  title: 'Endpoint did not answer 402 without payment',
  why: 'x402 is discover-by-402. A caller with no X-PAYMENT header must receive a 402 carrying the payment requirements, or it cannot learn the resource is paid at all.',
  fix: 'Return HTTP 402 with the challenge body when the X-PAYMENT header is absent.',
  check: (c) => c.httpStatus === 402 ? null : `HTTP ${c.httpStatus}`
});

RULES.push({
  id: 'body-not-json', severity: 'error', appliesTo: 'envelope', provenance: 'spec',
  title: '402 body is not parseable JSON',
  why: 'The challenge must be machine-readable. A client cannot extract payment requirements from a body it cannot parse.',
  fix: 'Return a JSON body with Content-Type: application/json.',
  check: (c) => c.parseError ? c.parseError.slice(0, 120) : null
});

RULES.push({
  id: 'oversized-body', severity: 'warn', appliesTo: 'envelope', provenance: 'observed (this probe)',
  title: '402 body exceeded the read cap',
  why: 'The probe reads at most 256 KB. The body was truncated, so the challenge contents could not be checked.',
  fix: 'A challenge body should be small. If yours is over 256 KB, something is wrong independent of this tool.',
  check: (c) => c.truncated ? 'body exceeded 256 KB' : null
});

// Every accepts-entry rule reads through this, so a missing or malformed
// accepts array degrades to "no entries" instead of throwing.
const entries = (c) => Array.isArray(c.body?.accepts) ? c.body.accepts : [];

RULES.push({
  id: 'missing-x402-version', severity: 'error', appliesTo: 'body', provenance: 'spec',
  title: 'x402Version is absent or not 1',
  why: 'Clients use x402Version to decide how to read the rest of the challenge.',
  fix: 'Include "x402Version": 1 at the top level of the 402 body.',
  check: (c) => c.body?.x402Version === 1 ? null : `x402Version = ${JSON.stringify(c.body?.x402Version)}`
});

RULES.push({
  id: 'accepts-empty', severity: 'error', appliesTo: 'body', provenance: 'spec',
  title: 'accepts is missing, not an array, or empty',
  why: 'accepts carries the payment requirements. With none, there is nothing a client can pay.',
  fix: 'Include a non-empty accepts array, one entry per accepted scheme/network pair.',
  check: (c) => entries(c).length > 0 ? null
    : `accepts = ${JSON.stringify(c.body?.accepts)}`
});

// Known USDC contracts. Kept deliberately short: a wrong entry here would
// produce a FALSE error finding on someone's working endpoint, which is worse
// than not checking at all.
const USDC = {
  'base': '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
  'base-sepolia': '0x036cbd53842c5426634e7929541ec2318f3dcf7e'
};
const KNOWN_NETWORKS = Object.keys(USDC);
const ATOMIC = /^[0-9]+$/;

// EIP-55: hex address whose casing is not all-upper and not all-lower.
const isChecksummed = (a) => /^0x[0-9a-fA-F]{40}$/.test(a) &&
  a.slice(2) !== a.slice(2).toLowerCase() && a.slice(2) !== a.slice(2).toUpperCase();

// Report the first offending entry only. A caller fixes one thing at a time,
// and ten copies of the same finding is noise.
const firstEntryWhere = (c, pred) => {
  const es = entries(c);
  for (let i = 0; i < es.length; i++) if (pred(es[i])) return { i, e: es[i] };
  return null;
};

RULES.push({
  id: 'output-schema-null', severity: 'error', appliesTo: 'body',
  provenance: 'observed (Coinbase CDP facilitator, 2026-07-17)',
  title: 'outputSchema is explicitly null',
  why: 'The CDP facilitator\'s schema is not nullable. An explicit null is rejected where an absent field is accepted.',
  fix: 'Omit the outputSchema field entirely rather than sending null.',
  check: (c) => {
    const hit = firstEntryWhere(c, (e) => e.outputSchema === null);
    return hit ? `accepts[${hit.i}].outputSchema === null` : null;
  }
});

RULES.push({
  id: 'amount-not-atomic-string', severity: 'error', appliesTo: 'body', provenance: 'spec',
  title: 'maxAmountRequired is not an atomic-unit string',
  why: 'The amount must be a decimal string in the asset\'s smallest unit — USDC has 6 decimals, so $9 is "9000000". A number, or a string containing a decimal point, will be misread or rejected.',
  fix: 'Send maxAmountRequired as a string of digits in atomic units. For $9 USDC: "9000000".',
  check: (c) => {
    const hit = firstEntryWhere(c, (e) =>
      typeof e.maxAmountRequired !== 'string' || !ATOMIC.test(e.maxAmountRequired));
    return hit ? `accepts[${hit.i}].maxAmountRequired = ${JSON.stringify(hit.e.maxAmountRequired)}` : null;
  }
});

// FINAL FIX PASS, CRITICAL 1 + 2.
//
// This rule used to fire on `!want || asset !== want` at severity `error`.
// Both halves overreached on a working endpoint:
//
//   (1) `!want` meant an UNKNOWN network produced an error. x402's network set
//       is far wider than the two contracts above — avalanche, avalanche-fuji,
//       polygon, polygon-amoy, sei, iotex, solana, solana-devnet — so a healthy
//       Avalanche or Solana seller was told it had a settlement-breaking
//       defect. We cannot compare an asset against a contract we do not know.
//       An unrecognised network is already reported once, by
//       unknown-network-name; reporting it twice is not more information.
//
//   (2) `error` / "cannot settle" asserted more than the check can know. The
//       `exact` scheme is EIP-3009 over ANY conforming ERC-20, so a Base
//       endpoint priced in EURC is legitimate, not broken. Downgraded to a
//       warn that states the observation and leaves the judgement to the
//       reader, who knows which token they meant to charge in.
RULES.push({
  id: 'asset-network-mismatch', severity: 'warn', appliesTo: 'body', provenance: 'spec',
  title: 'asset is not the USDC contract for this network',
  why: 'The asset on this entry is not the USDC contract this probe knows for the declared network. That is legitimate if you are deliberately pricing in another EIP-3009 token (EURC, for example) — the exact scheme works over any conforming ERC-20. If you meant to charge in USDC, this address is not it.',
  fix: 'If USDC was intended, use the USDC contract belonging to the network in the same accepts entry. If another token was intended, no change is needed.',
  check: (c) => {
    const hit = firstEntryWhere(c, (e) => {
      const want = USDC[String(e.network)];
      // Only when we KNOW this network's USDC contract and the asset differs.
      return Boolean(want) && String(e.asset).toLowerCase() !== want;
    });
    return hit ? `accepts[${hit.i}] network=${hit.e.network} asset=${hit.e.asset}` : null;
  }
});

// FINAL FIX PASS, IMPORTANT 3: EIP-712 and EIP-55 are EVM concepts. A healthy
// Solana entry carries no EIP-712 domain and a base58 payTo, and was getting a
// false `error` and a false `info` for it. The payTo shape is the cheapest
// honest signal for "this entry is on an EVM chain" that does not depend on
// this probe's short list of known network names.
//
// RE-REVIEW, FINDING A: keying the gate SOLELY on the shape of payTo turned
// one failure into its mirror image. A malformed or absent payTo on `base` —
// a typo, 39 hex digits, undefined — is not EVM-shaped, so both rules went
// silent; and since nothing else in the table inspects payTo, a genuinely
// broken Base entry could come back with no findings at all. Before the gate,
// the checksum rule at least caught it. A false negative is the same mistake
// as a false positive with the volume turned down, and it is the more
// dangerous of the two here: a caller who is told nothing is wrong stops
// looking.
//
// Widened so an entry counts as EVM if EITHER signal says so — the payTo is
// EVM-shaped, OR the network is one we know to be EVM (both entries in
// KNOWN_NETWORKS are Base, hence EVM). A malformed payTo on `base` is judged
// again; Solana, which satisfies neither arm, stays exempt.
const isEvmAddress = (a) => /^0x[0-9a-fA-F]{40}$/.test(String(a));
const isEvmEntry = (e) => isEvmAddress(e.payTo) || KNOWN_NETWORKS.includes(String(e.network));

RULES.push({
  id: 'missing-eip712-extra', severity: 'error', appliesTo: 'body', provenance: 'spec',
  title: 'scheme "exact" without the EIP-712 domain in extra',
  why: 'On an EVM chain the exact scheme is EIP-3009. Without the EIP-712 domain (name and version) the client cannot construct a signature the token contract will accept. Entries that are not EVM-shaped are not checked, because EIP-712 does not apply to them.',
  fix: 'Include extra: { name, version } matching the token contract\'s EIP-712 domain.',
  check: (c) => {
    const hit = firstEntryWhere(c, (e) =>
      isEvmEntry(e) && e.scheme === 'exact' && !(e.extra && e.extra.name && e.extra.version));
    return hit ? `accepts[${hit.i}].extra = ${JSON.stringify(hit.e.extra)}` : null;
  }
});

RULES.push({
  // RE-REVIEW, FINDING B: `warn` contradicted this rule's own text. A caution
  // light is a claim about the endpoint; this finding is a fact about THIS
  // PROBE'S list, not about their service. Demoted to info so a working
  // Avalanche or Solana seller is handed a note rather than a warning.
  id: 'unknown-network-name', severity: 'info', appliesTo: 'body', provenance: 'spec',
  title: 'network name is not one this probe recognises',
  // FINAL FIX PASS: once CRITICAL 1 stopped asset-network-mismatch from firing
  // on unknown networks, this became the only thing said about a healthy
  // Avalanche or Solana endpoint — and it told that seller a facilitator would
  // not route it and to switch to Base. Neither is something this probe knows.
  // It knows exactly one thing: the name is not on its short list.
  why: 'Network identifiers are exact strings, so a near-miss silently fails: "base-mainnet" is not "base". This probe only recognises ' + KNOWN_NETWORKS.join(' and ') + ', so plenty of perfectly valid x402 networks — avalanche, polygon, sei, iotex, solana and others — will appear here too. Seeing this does not mean the network is wrong.',
  fix: `Confirm the identifier is exactly the one x402 uses for your chain. If it is, nothing needs to change; this probe simply does not carry that network in its list (it knows ${KNOWN_NETWORKS.join(', ')}).`,
  check: (c) => {
    const hit = firstEntryWhere(c, (e) => !KNOWN_NETWORKS.includes(String(e.network)));
    return hit ? `accepts[${hit.i}].network = ${JSON.stringify(hit.e.network)}` : null;
  }
});

// RE-REVIEW ROUND 2 — the 16th rule, closing the residual left by FINDING A.
// Widening the EVM gate stopped a garbage payTo being silent, but it was then
// reported as `info: payto-not-checksummed` — a note about casing, folded into
// an `advisories` result. A string that is not an address at all is not an
// address missing its EIP-55 casing, and the consequence is not cosmetic:
// there is nowhere for the money to go. Under-reporting a settlement-breaking
// defect is the same quiet failure mode as over-reporting a working endpoint,
// and this branch closes both.
//
// Deliberately scoped to networks we KNOW are EVM. For a chain whose address
// format we do not hold, silence is correct: calling a valid base58 Solana
// address malformed would be exactly the false accusation this tool exists not
// to make.
RULES.push({
  id: 'payto-not-an-address', severity: 'error', appliesTo: 'body', provenance: 'spec',
  title: 'payTo is not a valid address for this network',
  why: 'payTo is the account the payment is sent to. On an EVM network it must be a 20-byte hex address (0x followed by 40 hex characters). This value is not one — it is absent, the wrong length, or contains characters that are not hex — so there is no account for a client to pay and the payment cannot be constructed at all.',
  fix: 'Set payTo to the receiving wallet address for this network, in full 0x-prefixed 40-hex-character form.',
  check: (c) => {
    const hit = firstEntryWhere(c, (e) =>
      KNOWN_NETWORKS.includes(String(e.network)) && !isEvmAddress(e.payTo));
    if (!hit) return null;
    // Report the value verbatim so the caller can see their own typo, but
    // never let a hostile or accidental 5 KB string into the finding.
    const shown = hit.e.payTo === undefined ? '(absent)' : JSON.stringify(hit.e.payTo);
    const clipped = shown.length > 80 ? `${shown.slice(0, 80)}… (${shown.length} chars)` : shown;
    return `accepts[${hit.i}].payTo = ${clipped}`;
  }
});

RULES.push({
  id: 'payto-not-checksummed', severity: 'info', appliesTo: 'body', provenance: 'spec',
  title: 'payTo is not a checksummed address',
  why: 'EIP-55 casing is a free typo check. An all-lowercase address is valid but discards it. Only EVM addresses are checked — EIP-55 has no meaning for a base58 address on a non-EVM chain.',
  fix: 'Emit payTo in EIP-55 checksummed form.',
  check: (c) => {
    // FINAL FIX PASS, IMPORTANT 3: `!isChecksummed(...)` was true for every
    // non-EVM payTo, so a base58 Solana address drew a finding about a
    // convention that does not exist on its chain.
    //
    // RE-REVIEW ROUND 2: the gate is now `isEvmAddress(e.payTo)` rather than
    // `isEvmEntry(e)`. One defect, one finding — a value that is not an address
    // is reported once, by payto-not-an-address, and must not ALSO be described
    // as an address that merely lacks its checksum casing. This says exactly
    // what the rule means: it judges casing, so it needs something that IS an
    // address to judge.
    const hit = firstEntryWhere(c, (e) => isEvmAddress(e.payTo) && !isChecksummed(String(e.payTo)));
    return hit ? `accepts[${hit.i}].payTo = ${hit.e.payTo}` : null;
  }
});

RULES.push({
  id: 'no-timeout-declared', severity: 'info', appliesTo: 'body', provenance: 'spec',
  title: 'maxTimeoutSeconds is absent',
  why: 'Without it a client cannot know how long the quote is good for, and must guess.',
  fix: 'Include maxTimeoutSeconds on each accepts entry.',
  check: (c) => {
    const hit = firstEntryWhere(c, (e) => typeof e.maxTimeoutSeconds !== 'number');
    return hit ? `accepts[${hit.i}] has no numeric maxTimeoutSeconds` : null;
  }
});

RULES.push({
  id: 'challenge-cacheable', severity: 'warn', appliesTo: 'envelope',
  provenance: 'observed (ours, 2026-08-15)',
  title: '402 challenge is cacheable',
  why: 'A CDN will happily cache a 402. A cached challenge hands a paying client stale payment requirements — an old price, or an item that has since sold. We hit exactly this on our own endpoint: a cached challenge kept serving a body from a previous deploy.',
  fix: 'Send Cache-Control: no-store on every 402 response.',
  check: (c) => {
    const cc = String(c.headers['cache-control'] || '');
    return /no-store/i.test(cc) ? null : `cache-control: ${cc || '(absent)'}`;
  }
});

// FINAL FIX PASS, IMPORTANT 6: this rule used to warn that "payment headers
// are not exposed", judging a response it never fetched. The headers a browser
// x402 client actually reads — X-PAYMENT-RESPONSE and friends — ride on the
// SETTLEMENT 200, which this probe does not request; the 402 carries its
// requirements in the body, where CORS exposure is irrelevant. So the absence
// of access-control-expose-headers on THIS response is not evidence of
// anything being wrong. It fired on our own endpoint, most likely falsely.
// Kept (deleting it would silently change the rule count) but demoted to info
// and reworded to say only what this probe can see, and to say plainly what it
// cannot.
RULES.push({
  id: 'cors-headers-not-exposed', severity: 'info', appliesTo: 'envelope',
  provenance: 'observed (x402-foundation/x402#2112)',
  title: 'browser clients will need payment headers exposed on the settlement response',
  why: 'This endpoint sends CORS headers, so it may serve browser clients. A browser can only read response headers named in access-control-expose-headers, and the headers an x402 browser client needs (X-PAYMENT-RESPONSE and any extension headers) arrive on the settlement 200 that follows a successful payment. This probe requests only the 402 and cannot confirm what the settlement response sends, so this is a reminder, not a finding about the response examined here.',
  fix: 'If browser clients are in scope, make sure the settlement response sets access-control-expose-headers to include X-PAYMENT-RESPONSE and any extension response headers. Nothing needs to change on the 402 itself.',
  check: (c) => {
    if (!c.headers['access-control-allow-origin']) return null; // not a CORS endpoint
    const ex = String(c.headers['access-control-expose-headers'] || '');
    return ex.trim() === ''
      ? 'this 402 sets access-control-allow-origin and declares no access-control-expose-headers; the settlement response was not probed'
      : null;
  }
});

RULES.push({
  id: 'bazaar-ext-inside-accepts', severity: 'warn', appliesTo: 'body',
  provenance: 'observed (ours, 2026-08-14)',
  title: 'Bazaar extension declared inside an accepts entry',
  why: 'Entries in accepts are forwarded verbatim to the facilitator as paymentRequirements, and that schema is strict — an unknown field is rejected outright with HTTP 400.',
  fix: 'Declare extensions at the TOP LEVEL of the 402 body, not inside an accepts entry.',
  check: (c) => {
    const hit = firstEntryWhere(c, (e) => e.extensions !== undefined);
    return hit ? `accepts[${hit.i}].extensions is present` : null;
  }
});

export function runRules(challenge) {
  const findings = [];
  const skipBody = bodyUnusable(challenge);
  for (const rule of RULES) {
    if (skipBody && rule.appliesTo === 'body') continue;
    let evidence = null;
    try {
      evidence = rule.check(challenge);
    } catch {
      continue; // a rule that throws is never allowed to break a probe
    }
    if (evidence !== null && evidence !== undefined) {
      const { id, severity, title, why, fix, provenance } = rule;
      findings.push({ id, severity, title, why, fix, provenance, evidence });
    }
  }
  return findings;
}
