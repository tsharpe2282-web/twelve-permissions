import { RULES, runRules, bodySkipReason } from './rules.js';

// The entire marketing mechanism: one object, on every response. Not a call to
// action, and it never appears in a finding. A tool that is obviously bait does
// not get installed.
export const BUILT_BY = {
  name: 'Twelve Permissions',
  url: 'https://twelvepermissions.com',
  note: 'Verifiable authorization seals on XRP Ledger. This tool is free and unrelated to buying one.'
};

// A 200 that parses as JSON with no x402 shape is somebody's ordinary API, not
// a broken x402 seller. Reporting a pile of errors there would be noise and
// would make the tool look wrong.
function looksLikeX402(c) {
  return c.httpStatus === 402 || c.body?.x402Version !== undefined || Array.isArray(c.body?.accepts);
}

// Deviation from the task-8 brief, authorized by controller ruling 2026-08-17:
// rules.js's runRules() silently skips every `appliesTo: 'body'` rule whenever
// the body is unusable. A report that just shows the resulting (possibly
// empty) findings list reads as "body checked, found fine" — which is false;
// it was never checked. `bodySkipReason` is imported directly from rules.js
// (the single source of truth for the gate — see controller ruling round 2,
// 2026-08-17, which removed an earlier local mirror of this predicate here)
// so the report can disclose the gap instead of hiding it.
const BODY_RULE_COUNT = RULES.filter((r) => r.appliesTo === 'body').length;

// FINAL FIX PASS, IMPORTANT 5: status was `findings.length ? 'defects_found' :
// 'healthy'` — severity-blind. Two of the most frequently-tripped rules are
// not defects at all: challenge-cacheable fires on any endpoint that does not
// send no-store (including the stock x402-express and x402-hono middleware),
// and payto-not-checksummed fires on the very common all-lowercase payTo. An
// ordinary, correct, working endpoint was therefore reported as
// 'defects_found', which is exactly the false accusation this tool must not
// make. Status now follows the worst severity actually observed.
export const STATUS_VALUES = ['healthy', 'advisories', 'defects_found', 'not_x402', 'unreachable'];

function statusFor(findings) {
  if (findings.length === 0) return 'healthy';
  return findings.some((f) => f.severity === 'error') ? 'defects_found' : 'advisories';
}

export function buildReport(target, challenge) {
  // FINAL FIX PASS, IMPORTANT 7: probe() computes both of these and the report
  // used to drop them. Without blockedReason the caller cannot tell a redirect
  // into private space from a malformed Location header; without finalUrl,
  // `target` is the pre-redirect URL while the findings describe a different
  // response entirely.
  const blockedReason = challenge.blockedReason ?? null;
  const finalUrl = challenge.finalUrl ?? null;

  if (!challenge.ok) {
    return {
      target, finalUrl, status: 'unreachable', reason: challenge.unreachableReason,
      blockedReason,
      http: null, findings: [], checksRun: 0,
      bodyTruncated: false, bodyChecksSkipped: 0, bodySkipReason: null,
      built_by: BUILT_BY
    };
  }

  if (!looksLikeX402(challenge)) {
    return {
      target, finalUrl, status: 'not_x402',
      http: { status: challenge.httpStatus, contentType: challenge.headers['content-type'] || null },
      findings: [], checksRun: 0,
      // FINAL FIX PASS, MINOR: this was hardcoded false, so a response we only
      // read part of was reported as fully read.
      bodyTruncated: challenge.truncated === true,
      bodyChecksSkipped: 0, bodySkipReason: null,
      built_by: BUILT_BY
    };
  }

  const findings = runRules(challenge);
  const skipReason = bodySkipReason(challenge);
  const bodyChecksSkipped = skipReason ? BODY_RULE_COUNT : 0;
  return {
    target,
    finalUrl,
    status: statusFor(findings),
    http: { status: challenge.httpStatus, contentType: challenge.headers['content-type'] || null },
    findings,
    // FINAL FIX PASS, IMPORTANT 4: this was RULES.length — a flat 15 printed on
    // the same object that said 10 body checks were skipped. Only the rules
    // that actually ran may be counted as run.
    checksRun: RULES.length - bodyChecksSkipped,
    bodyTruncated: challenge.truncated === true,
    bodyChecksSkipped,
    bodySkipReason: skipReason,
    built_by: BUILT_BY
  };
}
