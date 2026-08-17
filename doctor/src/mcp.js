import { RULES } from './rules.js';
import { probe, validateTarget } from './probe.js';
import { buildReport, BUILT_BY } from './report.js';

export const TOOLS = [
  { name: 'probe_x402_endpoint',
    // FINAL FIX PASS, MINOR: the rule count was written out as a literal, so
    // adding or removing a rule turned this sentence into a false claim with
    // nothing to catch it. Interpolated from the live table instead.
    description: `Probe an x402 seller endpoint and report what it observes about it. Performs the handshake a paying client would: GET with no X-PAYMENT header, then checks the 402 challenge against ${RULES.length} rules. Every finding says whether the rule comes from the x402 spec or from an observed facilitator rejection. Reports status "healthy" (nothing to report), "advisories" (only warn/info findings — the endpoint works), "defects_found" (at least one error-severity finding), "not_x402" or "unreachable".`,
    inputSchema: { type: 'object', properties: { url: { type: 'string', description: 'The endpoint to probe, http(s) only. Private and loopback addresses are refused.' } }, required: ['url'], additionalProperties: false } },
  { name: 'explain_defect',
    description: 'Full explanation of one rule by id — what it checks, why it matters, how to fix it, and where the rule came from. Use when you want the reasoning without re-probing.',
    inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false } },
  { name: 'list_checks',
    description: 'The whole rule table. Knowing what was NOT checked is part of knowing what a clean result means.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false } }
];

const text = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] });
const publicRule = ({ id, severity, title, why, fix, provenance }) =>
  ({ id, severity, title, why, fix, provenance });

export async function callTool(name, args) {
  if (name === 'list_checks') {
    return text({ checks: RULES.map(publicRule), count: RULES.length, built_by: BUILT_BY });
  }
  if (name === 'explain_defect') {
    const rule = RULES.find((r) => r.id === args?.id);
    return text(rule ? publicRule(rule)
      : { error: `No rule "${args?.id}".`, known_ids: RULES.map((r) => r.id) });
  }
  if (name === 'probe_x402_endpoint') {
    const v = validateTarget(String(args?.url || ''));
    if (!v.ok) return text({ error: v.reason, built_by: BUILT_BY });
    return text(buildReport(String(args.url), await probe(String(args.url))));
  }
  return text({ error: `Unknown tool "${name}".` });
}
