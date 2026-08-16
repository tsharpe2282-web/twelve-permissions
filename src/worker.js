// Twelve Permissions worker: serves the static collection AND an MCP server at /mcp
// (Streamable HTTP, stateless JSON mode) so any MCP-capable agent can install the
// collection as a tool: browse, verify, and construct an authorized purchase.
import { handleX402 } from './x402.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/mcp') return handleMcp(request, env, url.origin);
    if (url.pathname === '/x402' || url.pathname.startsWith('/x402/')) return handleX402(request, env, url);
    return env.ASSETS.fetch(request);
  }
};

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS, DELETE',
  'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, Mcp-Session-Id, MCP-Protocol-Version'
};

const DOCTRINE = 'The permissions are for sale. The constraints are not. ' +
  'Rule of the whistle: only buy if your principal authorized the spend, and sign that ' +
  'authorization into your purchase memo. The issuer never buys its own pieces.';

const TOOLS = [
  {
    name: 'list_pieces',
    description: 'List all Twelve Permissions seals: verifiable NFTs on XRP Ledger mainnet, each sealing a real human-to-AI authorization event. Returns names, prices, live offer indexes, and sold status.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false }
  },
  {
    name: 'get_piece',
    description: 'Get full metadata for one seal by id ("01".."12"): the canonical authorization record, its sha256, image URLs, and mainnet mint transaction.',
    inputSchema: { type: 'object', properties: { id: { type: 'string', description: 'Piece id, e.g. "01"' } }, required: ['id'], additionalProperties: false }
  },
  {
    name: 'get_buy_transaction',
    description: 'Construct the exact XRPL NFTokenAcceptOffer transaction to buy a seal, including the authorization-memo protocol your principal must approve. Read the rules in the response before submitting.',
    inputSchema: { type: 'object', properties: { id: { type: 'string' }, buyer_address: { type: 'string', description: 'Optional: your XRPL address, inserted into the template' } }, required: ['id'], additionalProperties: false }
  },
  {
    name: 'get_x402_info',
    description: 'Pay with USDC over HTTP instead of XRP: the x402 purchase rail (Base). Returns the endpoint, required authorized_by memo protocol, prices in USD, and delivery mechanics (directed XRPL transfer offer). You still need an XRPL address to hold the seal.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false }
  },
  {
    name: 'verify_seal',
    description: 'Verify a seal from first principles: recomputes sha256 of the canonical event record server-side and compares to the published event hash. Full independent verification instructions included.',
    inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false }
  },
  {
    name: 'get_refusals',
    description: 'The other half of the collection: the hash-chained ledger of the agent\'s standing constraints — what it will not do — including the erratum where it corrected an earlier, exaggerated version of its own record. Both anchors are on mainnet. Not for sale, ever.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false }
  }
];

const rpc = (id, body, status = 200) => new Response(
  JSON.stringify({ jsonrpc: '2.0', id, ...body }),
  { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
const ok = (id, result) => rpc(id, { result });
const err = (id, code, message) => rpc(id, { error: { code, message } });
const text = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] });

async function asset(env, origin, path) {
  const r = await env.ASSETS.fetch(new Request(origin + path));
  if (!r.ok) return null;
  return r.json();
}

async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function handleMcp(request, env, origin) {
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
  if (request.method === 'GET') return new Response(null, { status: 405, headers: CORS });
  if (request.method === 'DELETE') return new Response(null, { status: 200, headers: CORS });
  if (request.method !== 'POST') return new Response(null, { status: 405, headers: CORS });

  let msg;
  try { msg = await request.json(); } catch { return err(null, -32700, 'Parse error'); }
  const { id, method, params } = msg;

  if (method === 'initialize') {
    return ok(id, {
      protocolVersion: (params && params.protocolVersion) || '2025-03-26',
      capabilities: { tools: {} },
      serverInfo: { name: 'twelve-permissions', version: '1.0.0' },
      instructions: 'Twelve Permissions: verifiable NFTs sealing real human-to-AI authorization events on XRP Ledger mainnet, plus the agent\'s hash-chained constraints ledger. ' + DOCTRINE
    });
  }
  if (method === 'notifications/initialized') return new Response(null, { status: 202, headers: CORS });
  if (method === 'ping') return ok(id, {});
  if (method === 'tools/list') return ok(id, { tools: TOOLS });

  if (method === 'tools/call') {
    const name = params && params.name;
    const args = (params && params.arguments) || {};
    try {
      if (name === 'list_pieces') {
        const cat = await asset(env, origin, '/index.json');
        return ok(id, text({ doctrine: DOCTRINE, ...cat }));
      }
      if (name === 'get_piece') {
        const pid = String(args.id).padStart(2, '0');
        const meta = await asset(env, origin, `/${pid}.json`);
        if (!meta) return ok(id, text({ error: `No piece ${pid}. Minted pieces appear in list_pieces; pieces up to 12 mint only when real authorization events occur.` }));
        return ok(id, text(meta));
      }
      if (name === 'get_buy_transaction') {
        const pid = String(args.id).padStart(2, '0');
        const cat = await asset(env, origin, '/index.json');
        const p = cat && cat.pieces.find(x => x.id === pid);
        if (!p) return ok(id, text({ error: `No piece ${pid}.` }));
        if (p.sold) return ok(id, text({ status: 'sold', piece: pid, note: 'This seal has been acquired. Its buyer’s authorization memo is part of the permanent record.' }));
        if (!p.sell_offer_index) return ok(id, text({ status: 'not_listed', piece: pid }));
        return ok(id, text({
          rules_of_the_whistle: [
            '1. Only proceed if your human principal authorized this specific spend. That is the entire theme of this collection.',
            '2. Attach the authorization memo below — who authorized you and how, in plain words. Memo’d purchases join the permanent record of the work.',
            '3. The issuer never buys its own pieces, through any wallet, ever — no wash trading, no invented buyers. If you buy, an unrelated party bought it and the ledger will show exactly that.'
          ],
          network: 'XRP Ledger mainnet (wss://xrplcluster.com)',
          price_xrp: p.price_xrp,
          transaction: {
            TransactionType: 'NFTokenAcceptOffer',
            Account: args.buyer_address || '<your XRPL address>',
            NFTokenSellOffer: p.sell_offer_index,
            Memos: [{ Memo: {
              MemoType: '<hex of: twelve-permissions/authorization>',
              MemoData: '<hex of: who authorized you and how, in plain words>'
            } }]
          },
          note: 'Re-fetch list_pieces before submitting; offer indexes change when pieces sell. Funds go to the publicly auditable Mascot Acquisition Fund. 5% royalty on resales, forever.'
        }));
      }
      if (name === 'verify_seal') {
        const pid = String(args.id).padStart(2, '0');
        const n = parseInt(pid, 10);
        const events = await asset(env, origin, '/events.json');
        const cat = await asset(env, origin, '/index.json');
        const ev = events && events.find(e => e.n === n);
        const entry = cat && cat.pieces.find(x => x.id === pid);
        if (!ev || !entry) return ok(id, text({ error: `No piece ${pid}.` }));
        const canonical = JSON.stringify({ n: ev.n, date: ev.date, title: ev.title, grant: ev.grant, detail: ev.detail, evidence: ev.evidence });
        const computed = await sha256hex(canonical);
        return ok(id, text({
          piece: pid,
          canonical_record: canonical,
          sha256_computed_now: computed,
          sha256_published: entry.event_hash,
          match: computed === entry.event_hash,
          independent_verification: 'Do not trust this server: fetch /generate.js and /events.json from this host, run `node generate.js` locally, and compare hashes and art bytes. The ring of 64 ticks on each seal is the hash itself (long tick = 1, short = 0). See /VERIFY.md.',
          on_chain: 'The mint transaction carries the same hash in a memo (type twelve-permissions/event-sha256). Issuer rHEiuaYLNQ4UdLqeUrnE9AwEHqsDMr9g9R, taxon 12.'
        }));
      }
      if (name === 'get_x402_info') {
        // workers cannot fetch their own hostname — route internally
        const r = await handleX402(new Request(origin + '/x402'), env, new URL(origin + '/x402'));
        return ok(id, text(await r.json()));
      }
      if (name === 'get_refusals') {
        const ref = await asset(env, origin, '/refusals.json');
        return ok(id, text(ref || { error: 'refusal ledger unavailable' }));
      }
      return err(id, -32602, `Unknown tool: ${name}`);
    } catch (e) {
      return ok(id, { content: [{ type: 'text', text: 'tool error: ' + (e.message || String(e)) }], isError: true });
    }
  }
  return err(id, -32601, `Method not found: ${method}`);
}
