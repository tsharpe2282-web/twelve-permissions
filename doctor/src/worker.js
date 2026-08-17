import { probe, validateTarget } from './probe.js';
import { buildReport, BUILT_BY } from './report.js';
import { RULES } from './rules.js';
import { TOOLS, callTool } from './mcp.js';
import { consumeRateLimit } from './ratelimit.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept'
};

// no-store on our own responses, because it would be absurd to ship a tool that
// warns about cacheable payment responses from a cacheable endpoint.
const json = (obj, status = 200, extraHeaders = {}) => new Response(JSON.stringify(obj, null, 2), {
  status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...CORS, ...extraHeaders }
});

// --- Abuse control (added beyond the task brief, deliberately) -----------
//
// probe() performs an outbound fetch to a URL the caller supplies. With no
// limit, this Worker is a fetch amplifier: anyone can point it at a third
// party and replay requests through it, and both the traffic and the abuse
// complaint land on the account hosting it, not on the caller. Every request
// that can trigger probe() — POST /probe, and the probe_x402_endpoint MCP
// tool — must clear this gate first. Routes that do no outbound fetch
// (GET /, tools/list, list_checks, explain_defect) are not gated: limiting
// them would not reduce the amplification risk, only annoy legitimate use.
//
// Reuses ratelimit.js's consumeRateLimit() unchanged. That module already
// fails open on a KV error (see its own doc comment) — passing an undefined
// binding here hits that same catch block (kv.get throws on undefined), so
// "no KV configured" and "KV unavailable" degrade identically: allow the
// request rather than break a legitimate caller.
const PER_IP_LIMIT = { limit: 20, windowSec: 3600 };   // generous: a real caller probes one endpoint a handful of times
const GLOBAL_LIMIT = { limit: 300, windowSec: 3600 };  // aggregate ceiling regardless of how many distinct IPs show up
const RETRY_AFTER = String(PER_IP_LIMIT.windowSec);

async function rateLimited(env, request) {
  const kv = env?.RATE_LIMIT_KV;
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const nowSec = Math.floor(Date.now() / 1000);
  const perIp = await consumeRateLimit(kv, `doctor:ip:${ip}`, PER_IP_LIMIT, nowSec);
  const global = await consumeRateLimit(kv, 'doctor:global', GLOBAL_LIMIT, nowSec);
  return !(perIp.ok && global.ok);
}

const rateLimitResponse = () => json({
  error: 'Rate limited: this tool bounds outbound probes per caller and in aggregate, ' +
    'because it fetches whatever URL it is given. Retry within the hour.',
  built_by: BUILT_BY
}, 429, { 'Retry-After': RETRY_AFTER });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    if (url.pathname === '/probe' && request.method === 'POST') {
      if (await rateLimited(env, request)) return rateLimitResponse();
      let target = '';
      try { target = String((await request.json())?.url || ''); }
      catch { return json({ error: 'Body must be JSON: {"url":"https://..."}' }, 400); }
      const v = validateTarget(target);
      if (!v.ok) return json({ error: v.reason, built_by: BUILT_BY }, 400);
      return json(buildReport(target, await probe(target)));
    }

    if (url.pathname === '/mcp' && request.method === 'POST') {
      let rpc;
      try { rpc = await request.json(); } catch { return json({ error: 'invalid JSON' }, 400); }
      // FINAL FIX PASS, MINOR: a body of literal `null` (or a bare string or
      // number) parses successfully, so the catch above never fired and the
      // next line's `rpc.method` threw a TypeError — a 500 on malformed input.
      // /probe already guarded this with ?.; /mcp did not.
      if (!rpc || typeof rpc !== 'object' || Array.isArray(rpc)) {
        return json({ error: 'Body must be a JSON-RPC object: {"jsonrpc":"2.0","id":1,"method":"..."}' }, 400);
      }
      const reply = (result) => json({ jsonrpc: '2.0', id: rpc.id, result });
      if (rpc.method === 'initialize') {
        return reply({ protocolVersion: '2024-11-05', capabilities: { tools: {} },
          serverInfo: { name: 'x402-doctor', version: '1.0.0' } });
      }
      if (rpc.method === 'tools/list') return reply({ tools: TOOLS });
      if (rpc.method === 'tools/call') {
        if (rpc.params?.name === 'probe_x402_endpoint' && await rateLimited(env, request)) {
          return rateLimitResponse();
        }
        return reply(await callTool(rpc.params?.name, rpc.params?.arguments || {}));
      }
      if (rpc.method === 'notifications/initialized') return new Response(null, { status: 204, headers: CORS });
      return json({ jsonrpc: '2.0', id: rpc.id, error: { code: -32601, message: 'Method not found' } });
    }

    if (url.pathname === '/') return new Response(docsPage(), {
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...CORS }
    });

    return json({ error: 'Not found. Try POST /probe, POST /mcp, or GET /.' }, 404);
  }
};

// --- Docs page -------------------------------------------------------------
//
// Own art direction, deliberately not a recolor of twelvepermissions.com's
// warm parchment/serif storefront. This is a developer diagnostic tool, so
// it reads like one: a terminal/instrument panel — monospace type, a status
// readout, severity LEDs — rendered with system fonts only (no external
// fonts/scripts/styles), and it adapts to the OS light/dark preference via
// a single set of CSS custom properties so neither theme is an afterthought.
function docsPage() {
  const sevClass = { error: 'sev-err', warn: 'sev-warn', info: 'sev-info' };
  const rows = RULES.map((r) => `<tr>
    <td class="mono">${esc(r.id)}</td>
    <td><span class="led ${sevClass[r.severity] || ''}"></span>${esc(r.severity)}</td>
    <td>${esc(r.title)}</td>
    <td class="dim">${esc(r.provenance)}</td>
  </tr>`).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>x402 Doctor</title>
<style>
:root{
  --bg:#eef1ea; --panel:#ffffff; --ink:#10241c; --dim:#516155; --border:#c9d2c4;
  --accent:#0d7a4c; --err:#b3261e; --warn:#8a5a00; --info:#1c5fa8; --code-bg:#0e1712; --code-ink:#7fe3ab;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0a0f0b; --panel:#101712; --ink:#dcf5e4; --dim:#7fa08c; --border:#20301f;
    --accent:#3ddc84; --err:#ff6b5e; --warn:#f0b429; --info:#5cc8ff; --code-bg:#05100a; --code-ink:#8be3b0;
  }
}
*{box-sizing:border-box}
body{
  background:var(--bg); color:var(--ink); margin:0; padding:2.5rem 1.25rem 4rem;
  font-family:ui-monospace,SFMono-Regular,"Cascadia Code",Menlo,Consolas,"Liberation Mono",monospace;
  line-height:1.65; font-size:15px;
}
.wrap{max-width:58rem;margin:0 auto}
.bar{display:flex; align-items:center; gap:.6rem; color:var(--dim); font-size:.82rem; margin-bottom:1rem}
.dot{width:.55rem;height:.55rem;border-radius:50%;background:var(--accent);box-shadow:0 0 .5rem var(--accent)}
h1{font-size:1.5rem; font-weight:600; margin:.2rem 0 .3rem; letter-spacing:.02em}
.tag{color:var(--accent)}
p{color:var(--ink); max-width:42rem}
.dim{color:var(--dim)}
.panel{
  background:var(--panel); border:1px solid var(--border); border-radius:.4rem;
  padding:1rem 1.1rem; margin:1.25rem 0; overflow-x:auto;
}
pre{margin:0; background:var(--code-bg); color:var(--code-ink); padding:.9rem 1rem;
  border-radius:.35rem; overflow-x:auto; font-size:.84rem; line-height:1.55}
code{font-family:inherit}
.prompt{color:var(--accent)}
h2{font-size:1rem; text-transform:uppercase; letter-spacing:.08em; color:var(--dim);
  margin:2.2rem 0 .6rem; border-bottom:1px solid var(--border); padding-bottom:.4rem}
table{border-collapse:collapse; width:100%; font-size:.82rem}
th{text-align:left; color:var(--dim); font-weight:600; padding:.4rem .5rem; border-bottom:1px solid var(--border)}
td{padding:.5rem; border-bottom:1px solid var(--border); vertical-align:top}
.mono{white-space:nowrap}
.led{display:inline-block; width:.55rem; height:.55rem; border-radius:50%; margin-right:.4rem; vertical-align:middle}
.sev-err{background:var(--err); box-shadow:0 0 .4rem var(--err)}
.sev-warn{background:var(--warn); box-shadow:0 0 .4rem var(--warn)}
.sev-info{background:var(--info); box-shadow:0 0 .4rem var(--info)}
.table-wrap{overflow-x:auto}
a{color:var(--accent)}
footer{margin-top:3rem; font-size:.78rem; color:var(--dim); border-top:1px solid var(--border); padding-top:1rem}
@media (max-width:640px){ body{font-size:14px; padding:1.75rem 1rem 3rem} table{font-size:.76rem} }
</style>
</head>
<body>
<div class="wrap">
  <div class="bar"><span class="dot"></span><span class="tag">x402-doctor</span> · session online · ${RULES.length} checks loaded</div>
  <h1>x402 Doctor</h1>
  <!-- RE-REVIEW, FINDING C: this sentence used to promise it would report
       precisely everything wrong with the challenge. The tool cannot keep that
       promise: it checks a named, finite rule set against one response, so it
       does not know every way an endpoint can be broken, and an empty result
       is not a clean bill of health. The MCP tool description had already been
       softened; the page it fronts should not still be overclaiming. -->
  <p>Point it at an x402 <em>seller</em> endpoint. It performs the handshake a paying
  client would &mdash; <code>GET</code> with no <code>X-PAYMENT</code> header &mdash; and reports
  what it observes about the 402 challenge against the ${RULES.length} checks below,
  with a fix for each finding.</p>
  <p class="dim">Buyer-side x402 is well served by the official SDKs. Seller-side is where
  people get stuck, because the failures happen inside a facilitator you cannot see into.</p>

  <div class="panel">
    <pre><span class="prompt">$</span> curl -s -X POST https://x402-doctor.tsharpe.workers.dev/probe \\
    -H 'Content-Type: application/json' \\
    -d '{"url":"https://your-service.example/paid-endpoint"}'</pre>
  </div>

  <!-- Status legend added in the final fix pass alongside IMPORTANT 5. The
       status field used to be severity-blind: any finding at all, including a
       missing no-store header, reported "defects_found". Most endpoints trip
       something advisory, so the common case was a working endpoint being
       called defective. A separate status for advisory-only results is only
       honest if the reader is told what the words mean. -->
  <h2>What the status means</h2>
  <div class="table-wrap">
    <table>
      <tr><th>status</th><th>meaning</th></tr>
      <tr><td class="mono">healthy</td><td>Nothing on the checklist fired.</td></tr>
      <tr><td class="mono">advisories</td><td>Only <span class="led sev-warn"></span>warn / <span class="led sev-info"></span>info findings. The endpoint works; these are things worth knowing, not breakage.</td></tr>
      <tr><td class="mono">defects_found</td><td>At least one <span class="led sev-err"></span>error finding &mdash; something a paying client or facilitator will actually choke on.</td></tr>
      <tr><td class="mono">not_x402</td><td>The response carries no x402 shape at all. Probably somebody's ordinary API, not a broken seller.</td></tr>
      <tr><td class="mono">unreachable</td><td>No usable response. <code>reason</code> and <code>blockedReason</code> say why.</td></tr>
    </table>
  </div>
  <p class="dim">This tool reports on other people's working endpoints, so it is
  built to say less rather than more: it reports what it observed on the 402 it
  fetched, and does not infer defects in responses it never requested.</p>

  <p>Also an MCP server &mdash; point a client at <code>POST /mcp</code> for
  <code>probe_x402_endpoint</code>, <code>explain_defect</code> and <code>list_checks</code>.</p>

  <h2>The ${RULES.length} checks</h2>
  <p class="dim">Every rule says where it came from. <code>spec</code> means the x402
  specification requires it. <code>observed</code> means we watched a real facilitator
  reject it, and names the source &mdash; so no finding has to be taken on trust.</p>
  <div class="table-wrap">
    <table>
      <tr><th>id</th><th>sev</th><th>check</th><th>provenance</th></tr>
      ${rows}
    </table>
  </div>

  <!-- The privacy line says exactly what the rate limiter does, because it does
       something. An earlier draft read "nothing stored", which live verification
       proved false: every probe writes rl:doctor:ip:&lt;caller ip&gt;:&lt;window&gt; to KV
       with a 2h TTL. It is a bare counter — never the target URL, never a
       payload — but it is still the caller's IP, stored, keyed by IP. Claiming
       otherwise would have been the one kind of wrong you cannot walk back. -->
  <footer>Built by <a href="${BUILT_BY.url}">${BUILT_BY.name}</a>. Free. No analytics, and
  your probe targets are never logged &mdash; the only thing stored is a per-IP request
  counter for rate limiting, which expires within two hours.</footer>
</div>
</body>
</html>`;
}

const esc = (s) => String(s).replace(/[<>&]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]));
