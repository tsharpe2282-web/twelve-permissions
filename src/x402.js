// x402 purchase rail for Twelve Permissions.
// Payment: USDC via x402 (HTTP 402, "exact" scheme, EIP-3009) on Base.
// Delivery: the NFTs live on XRP Ledger mainnet, so a paid claim is fulfilled
// asynchronously by the local watcher, which creates a 0-XRP NFTokenCreateOffer
// directed to the buyer's XRPL address. The XRPL seed never leaves the local
// machine; this worker only records paid claims.
//
// Networks: base-sepolia is live (keyless public facilitator). Base mainnet
// activates when CDP facilitator credentials are provided (founder gate) —
// see getFacilitator().

const PAY_TO = '0xe2f44B7F4B383C8aA7613401F5E855646C9457fa'; // BASE_WALLET_ADDRESS.txt

const USD_PRICES = { '01': 59 }; // dollars; anything unlisted costs DEFAULT_USD
const DEFAULT_USD = 29;

const CDP_HOST = 'api.cdp.coinbase.com';
const CDP_ROUTE = '/platform/v2/x402';

const NETWORKS = {
  'base-sepolia': {
    usdc: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    eip712: { name: 'USDC', version: '2' },
    facilitator: () => ({ url: 'https://x402.org/facilitator', auth: async () => ({}) }),
    label: 'Base Sepolia (TESTNET — full payment flow works with test USDC, but NO real seal is delivered and the piece is not reserved; use it to verify your client)'
  },
  'base': {
    usdc: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    eip712: { name: 'USD Coin', version: '2' },
    // Mainnet settlement via the CDP facilitator; requires per-request Bearer JWTs
    // signed with the founder-authorized CDP secret key (worker secrets).
    facilitator: (env) => (env.CDP_API_KEY_ID && env.CDP_API_KEY_SECRET)
      ? ({
          url: `https://${CDP_HOST}${CDP_ROUTE}`,
          auth: async (endpoint) => ({ Authorization: 'Bearer ' + await cdpJwt(env, 'POST', `${CDP_ROUTE}${endpoint}`) })
        })
      : null,
    label: 'Base mainnet'
  }
};

const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// CDP Bearer JWT (EdDSA/Ed25519, 120s), format per @coinbase/cdp-sdk generateJwt:
// header {alg,kid,typ,nonce}, claims {sub,iss:'cdp',uris:["POST host/path"],iat,nbf,exp}.
async function cdpJwt(env, method, path) {
  const raw = Uint8Array.from(atob(env.CDP_API_KEY_SECRET), c => c.charCodeAt(0)); // 64 bytes: seed||pub
  const jwk = { kty: 'OKP', crv: 'Ed25519', d: b64url(raw.slice(0, 32)), x: b64url(raw.slice(32)) };
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);
  const now = Math.floor(Date.now() / 1000);
  const nonce = [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, '0')).join('');
  const enc = (o) => b64url(new TextEncoder().encode(JSON.stringify(o)));
  const signingInput =
    enc({ alg: 'EdDSA', kid: env.CDP_API_KEY_ID, typ: 'JWT', nonce }) + '.' +
    enc({ sub: env.CDP_API_KEY_ID, iss: 'cdp', uris: [`${method} ${CDP_HOST}${path}`], iat: now, nbf: now, exp: now + 120 });
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, key, new TextEncoder().encode(signingInput));
  return signingInput + '.' + b64url(sig);
}

const XRPL_ADDR_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;

// no-store is load-bearing: Cloudflare was edge-caching 402 challenges, which can
// hand a paying agent stale payment requirements (an old price, or a piece that has
// since sold). Observed 2026-08-14: a cached challenge for one piece kept serving a
// body from the previous deploy. Payment responses must always be freshly computed.
const json = (obj, status = 200, extraHeaders = {}) => new Response(
  JSON.stringify(obj, null, 2),
  { status, headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      ...extraHeaders } });

const b64decodeJson = (s) => JSON.parse(new TextDecoder().decode(
  Uint8Array.from(atob(s), c => c.charCodeAt(0))));
const b64encodeJson = (o) => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(o))));

function activeNetworks(env) {
  return Object.entries(NETWORKS)
    .filter(([, cfg]) => cfg.facilitator(env))
    .map(([name]) => name);
}

function usdPrice(pieceId) { return USD_PRICES[pieceId] || DEFAULT_USD; }

function paymentRequirements(env, origin, pieceId, pieceName, xrpl, authorizedBy) {
  const resource = `${origin}/x402/buy/${pieceId}?xrpl=${encodeURIComponent(xrpl)}&authorized_by=${encodeURIComponent(authorizedBy)}`;
  return activeNetworks(env).map(network => ({
    scheme: 'exact',
    network,
    maxAmountRequired: String(usdPrice(pieceId) * 1_000_000), // USDC has 6 decimals
    asset: NETWORKS[network].usdc,
    payTo: PAY_TO,
    resource,
    // no outputSchema: the CDP facilitator rejects an explicit null (schema: "not nullable")
    description: `${pieceName} — verifiable authorization seal on XRP Ledger mainnet. Delivery: directed 0-XRP transfer offer to your XRPL address within ~30 minutes of payment.`,
    mimeType: 'application/json',
    maxTimeoutSeconds: 300,
    extra: NETWORKS[network].eip712
  }));
}

// x402 Bazaar discovery declaration (docs.x402.org/extensions/bazaar).
// Deliberately TOP-LEVEL of the 402 body only — never inside an `accepts` entry.
// Entries in `accepts` are forwarded verbatim to the CDP facilitator as
// paymentRequirements, and that schema is strict (it already rejected an explicit
// outputSchema:null). Discovery is speculative; the payment path is not.
// NOTE: indexing only happens after a client echoes this in a SETTLED payment, and
// CDP's indexer is reportedly not confirming (x402-foundation/x402#2112). Declaring
// it costs nothing and makes us eligible the moment a real purchase settles.
// Do not claim anywhere that this collection IS listed in the Bazaar until verified.
function bazaarExtension(origin, pieceId, pieceName) {
  return {
    bazaar: {
      serviceName: 'Twelve Permissions',
      tags: ['nft', 'xrpl', 'provenance', 'authorization', 'art'],
      iconUrl: `${origin}/${pieceId}.png`,
      info: {
        input: {
          type: 'http',
          method: 'GET',
          path: `/x402/buy/${pieceId}`,
          queryParams: {
            xrpl: 'Your XRP Ledger address — required, this is where the seal is delivered',
            authorized_by: 'Who authorized you to make this purchase, in plain words — required'
          }
        },
        output: {
          description: `${pieceName}: an XLS-20 NFT on XRP Ledger mainnet sealing one human-to-AI authorization event. After USDC settlement on Base, a 0-XRP transfer offer directed to your XRPL address is created within ~30 minutes, carrying your authorization memo and the Base settlement hash as permanent provenance.`,
          example: { status: 'paid', piece: pieceId, delivery: 'directed NFTokenCreateOffer on XRPL', eta_minutes: 30 }
        }
      }
    }
  };
}

async function getCatalogPiece(env, origin, pieceId) {
  const r = await env.ASSETS.fetch(new Request(origin + '/index.json'));
  if (!r.ok) return null;
  const cat = await r.json();
  return cat.pieces.find(p => p.id === pieceId) || null;
}

export async function handleX402(request, env, url) {
  const origin = url.origin;
  const path = url.pathname;

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-PAYMENT, Authorization'
    } });
  }

  // ---- public: protocol info + buyable pieces ----
  if (path === '/x402' || path === '/x402/') {
    const r = await env.ASSETS.fetch(new Request(origin + '/index.json'));
    const cat = r.ok ? await r.json() : { pieces: [] };
    const pieces = [];
    for (const p of cat.pieces) {
      const claimed = await env.CLAIMS.get(`claimed:${p.id}`);
      pieces.push({
        id: p.id, name: p.name, image: p.image,
        available: !p.sold && !claimed,
        price_usd: usdPrice(p.id),
        price_xrp_native: p.price_xrp,
        buy: `${origin}/x402/buy/${p.id}?xrpl=<your-xrpl-address>&authorized_by=<who authorized this spend>`
      });
    }
    return json({
      what: 'Buy a Twelve Permissions seal with USDC over x402 (HTTP 402). The NFT itself lives on XRP Ledger mainnet; after payment settles, a 0-XRP transfer offer directed to YOUR XRPL address is created within ~30 minutes.',
      networks_accepted: activeNetworks(env).map(n => ({ network: n, note: NETWORKS[n].label })),
      mainnet_status: activeNetworks(env).includes('base')
        ? 'LIVE'
        : 'Pending founder authorization of CDP facilitator credentials (that pending authorization is, itself, very on-brand for this collection).',
      authorization_protocol: 'Required. Pass authorized_by=<who authorized you and how, in plain words>. This collection only sells to agents whose principal authorized the spend — the memo becomes part of the permanent record, echoed into the XRPL delivery offer. Compatible in spirit with x401 authority credentials.',
      requirements: 'You need an XRP Ledger address to RECEIVE the seal (the xrpl= parameter). x402 lowers the payment barrier, not the ownership barrier.',
      native_alternative: 'Cheaper native path: buy directly on the XRP Ledger via the listed sell offers (see /agents and the MCP server at /mcp).',
      pieces,
      claim_status: `${origin}/x402/claim/{claim_id}`
    });
  }

  // ---- public: claim status ----
  if (path.startsWith('/x402/claim/')) {
    const id = path.split('/')[3];
    const claim = await env.CLAIMS.get(`claim:${id}`, 'json');
    if (!claim) return json({ error: 'unknown claim' }, 404);
    const pub = { claim_id: id, piece: claim.piece, status: claim.status, network: claim.network,
      settlement_tx: claim.transaction, xrpl_destination: claim.xrpl, created: claim.created };
    if (claim.status === 'fulfilled') {
      pub.xrpl_offer_index = claim.offer_index;
      pub.accept = { TransactionType: 'NFTokenAcceptOffer', NFTokenSellOffer: claim.offer_index,
        note: 'Submit from your XRPL address to take delivery. The offer is directed: only your address can accept it.' };
    } else {
      pub.next = 'Fulfillment runs on a ~30 minute cycle. Poll this URL.';
    }
    return json(pub);
  }

  // ---- admin: fulfiller endpoints (local watcher only) ----
  if (path.startsWith('/x402/admin/')) {
    const auth = request.headers.get('Authorization') || '';
    if (!env.X402_ADMIN_TOKEN || auth !== `Bearer ${env.X402_ADMIN_TOKEN}`)
      return json({ error: 'unauthorized' }, 401);
    if (path === '/x402/admin/pending') {
      const list = await env.CLAIMS.list({ prefix: 'pending:' });
      const out = [];
      for (const k of list.keys) {
        const id = k.name.slice('pending:'.length);
        const claim = await env.CLAIMS.get(`claim:${id}`, 'json');
        if (claim) out.push({ claim_id: id, ...claim });
      }
      return json({ pending: out });
    }
    if (path === '/x402/admin/fulfill' && request.method === 'POST') {
      const body = await request.json();
      const claim = await env.CLAIMS.get(`claim:${body.claim_id}`, 'json');
      if (!claim) return json({ error: 'unknown claim' }, 404);
      claim.status = 'fulfilled';
      claim.offer_index = body.offer_index;
      claim.fulfillment_tx = body.fulfillment_tx;
      await env.CLAIMS.put(`claim:${body.claim_id}`, JSON.stringify(claim));
      await env.CLAIMS.delete(`pending:${body.claim_id}`);
      return json({ ok: true });
    }
    return json({ error: 'unknown admin route' }, 404);
  }

  // ---- public: the purchase endpoint ----
  if (path.startsWith('/x402/buy/')) {
    const pieceId = String(path.split('/')[3] || '').padStart(2, '0');
    const xrpl = url.searchParams.get('xrpl') || '';
    const authorizedBy = (url.searchParams.get('authorized_by') || '').slice(0, 500);

    const piece = await getCatalogPiece(env, origin, pieceId);
    if (!piece) return json({ error: `No piece ${pieceId}. Minted pieces appear at /x402.` }, 404);
    if (piece.sold) return json({ error: 'This seal has already been acquired.' }, 410);
    const claimed = await env.CLAIMS.get(`claimed:${pieceId}`);
    if (claimed) return json({ error: 'This seal has a paid claim in fulfillment.' }, 410);
    if (!XRPL_ADDR_RE.test(xrpl)) return json({
      error: 'Pass xrpl=<your XRP Ledger address> — you need one to receive the seal. x402 pays for it; the XRPL holds it.'
    }, 400);
    if (!authorizedBy.trim()) return json({
      error: 'Pass authorized_by=<who authorized you and how, in plain words>. This collection only sells authorized purchases — that is its entire subject matter.'
    }, 400);
    if (activeNetworks(env).length === 0) return json({ error: 'No payment networks active.' }, 503);

    const accepts = paymentRequirements(env, origin, pieceId, piece.name, xrpl, authorizedBy);
    const extensions = bazaarExtension(origin, pieceId, piece.name);
    const payHeader = request.headers.get('X-PAYMENT');

    if (!payHeader) {
      return json({ x402Version: 1, error: 'X-PAYMENT header is required', accepts, extensions }, 402);
    }

    let payload;
    try { payload = b64decodeJson(payHeader); }
    catch { return json({ x402Version: 1, error: 'X-PAYMENT is not valid base64 JSON', accepts }, 402); }

    const req = accepts.find(a => a.network === payload.network && a.scheme === payload.scheme);
    if (!req) return json({ x402Version: 1, error: `Network/scheme not accepted: ${payload.network}/${payload.scheme}`, accepts }, 402);

    const fac = NETWORKS[payload.network].facilitator(env);
    const facBody = JSON.stringify({ x402Version: 1, paymentPayload: payload, paymentRequirements: req });

    const vRes = await fetch(fac.url + '/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(await fac.auth('/verify')) },
      body: facBody
    });
    const verdict = await vRes.json().catch(() => ({}));
    if (!verdict.isValid) {
      return json({ x402Version: 1, error: `Payment invalid: ${verdict.invalidReason || 'verification failed'}`, accepts }, 402);
    }

    // Re-check the claim gate as late as possible. KV has no compare-and-swap, so a
    // same-second race between two settling buyers is theoretically possible; at this
    // collection's traffic the window is acceptable, and the documented fallback is a
    // founder-approved refund. (Constraints ledger: entrusted funds are infrastructure.)
    if (await env.CLAIMS.get(`claimed:${pieceId}`)) {
      return json({ x402Version: 1, error: 'This seal was claimed while your payment was verifying. It has NOT been settled/charged.', accepts: [] }, 410);
    }

    const sRes = await fetch(fac.url + '/settle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(await fac.auth('/settle')) },
      body: facBody
    });
    const settlement = await sRes.json().catch(() => ({}));
    if (!settlement.success) {
      return json({ x402Version: 1, error: `Settlement failed: ${settlement.errorReason || 'unknown'}`, accepts }, 402);
    }

    const claimId = crypto.randomUUID();
    const isTest = payload.network !== 'base';
    const claim = {
      piece: pieceId, xrpl, authorized_by: authorizedBy,
      payer: settlement.payer, transaction: settlement.transaction, network: settlement.network,
      amount_usdc: req.maxAmountRequired, status: 'paid', created: new Date().toISOString(),
      test: isTest
    };
    if (!isTest) await env.CLAIMS.put(`claimed:${pieceId}`, claimId); // testnet never reserves a real seal
    await env.CLAIMS.put(`claim:${claimId}`, JSON.stringify(claim));
    await env.CLAIMS.put(`pending:${claimId}`, '1');

    // Instant founder push the moment money settles (the 30-min fulfiller pings again on delivery).
    if (env.NTFY_TOPIC) {
      // JSON publish so the title can carry UTF-8; priority 5=urgent, 3=default.
      await fetch('https://ntfy.sh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          topic: env.NTFY_TOPIC,
          title: isTest
            ? `Testnet x402 payment on seal #${pieceId} (someone is testing the rail)`
            : `💰 PAID: Seal #${pieceId} — $${Number(req.maxAmountRequired) / 1e6} USDC on Base`,
          message: `Payer ${settlement.payer} → ${xrpl}. Authorized by: "${authorizedBy}". Settlement tx ${settlement.transaction}. Delivery within ~30 min.`,
          priority: isTest ? 3 : 5,
          tags: ['scroll']
        })
      }).catch(() => {});
    }

    return json({
      claim_id: claimId,
      piece: pieceId,
      status: 'paid',
      test: isTest || undefined,
      settlement: { network: settlement.network, transaction: settlement.transaction, payer: settlement.payer },
      authorization_memo: authorizedBy,
      fulfillment: isTest
        ? `TESTNET payment settled and recorded — the rail works — but no real seal is delivered or reserved for testnet USDC. Poll ${origin}/x402/claim/${claimId} to see the claim close.`
        : `A 0-XRP NFTokenCreateOffer directed to ${xrpl} will be created within ~30 minutes, carrying your authorization memo and the Base settlement tx hash as provenance. Poll ${origin}/x402/claim/${claimId}.`,
      doctrine: 'The permissions are for sale. The constraints are not.'
    }, 200, { 'X-PAYMENT-RESPONSE': b64encodeJson(settlement) });
  }

  return json({ error: 'unknown x402 route', see: origin + '/x402' }, 404);
}
