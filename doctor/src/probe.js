// ALL the I/O lives here. rules.js stays pure so the whole table is testable
// offline; this file is the only thing that touches the network.
export const MAX_BYTES = 256 * 1024;
export const TIMEOUT_MS = 10_000;
// FIX ROUND 1 (controller ruling, deviates from task-7-brief.md): the brief
// used `redirect: 'follow'`, which hands redirect-following to the
// underlying fetch with no re-validation of where the chain lands. Treated
// as an oversight, not a deliberate tradeoff — closed by following
// redirects here ourselves, capped, with the SSRF guard re-run on every hop.
export const MAX_REDIRECTS = 3;

// FINAL FIX PASS, MINOR: the probe used to go out with whatever default UA the
// runtime supplied. Two problems. (1) Bot-filtered targets answer an
// unidentified client with 403, which looksLikeX402() then reports as
// `not_x402` — a false verdict on a genuinely working endpoint. (2) A third
// party whose endpoint we fetch is entitled to know who fetched it and where
// to look the tool up; unattributable traffic from a Worker is exactly what an
// operator blocks. Carries the URL so the answer is one click away.
export const USER_AGENT = 'x402-doctor/1.0 (+https://x402-doctor.tsharpe.workers.dev)';

// Without this the service is an SSRF tool: anyone could point it at cloud
// metadata endpoints or a private network and read the response back.
// FIX ROUND 3, MINOR (IPv4 list gaps): added 100.64.0.0/10 (CGNAT, RFC 6598
// — carrier-grade NAT space, not publicly routable) and 255.255.255.255
// (limited broadcast).
const PRIVATE = [
  /^127\./, /^10\./, /^192\.168\./, /^169\.254\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^255\.255\.255\.255$/,
  /^0\./, /^localhost$/i
];

// --- FIX ROUND 2, CRITICAL 1 --------------------------------------------
// A security review re-derived the guard and found five bypasses: the
// spelling-matching approach (a regex per known-bad literal) is a losing
// game — every fix invites the next spelling. The correct approach:
// normalise ANY IPv6 literal to its canonical 8-hextet numeric form, then
// range-check numerically. This single path replaces the old
// exactly-"::ffff:xxxx:xxxx"-shaped regex from round 1.

// Expand a bracket-stripped IPv6 literal (as produced by url.hostname,
// which is always syntactically valid IPv6 if present at all) into an
// array of eight 16-bit numbers. Handles "::" compression and a
// dotted-quad IPv4 tail (kept as defense-in-depth: url.hostname already
// normalises dotted IPv4-mapped/compatible tails to hex before we ever see
// them, but a caller could in principle hand this function a raw literal
// directly). Returns null if the string is not parseable as IPv6.
function expandIPv6(host) {
  let s = host;
  let ipv4Tail = null;

  const tailMatch = /(?:^|:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
  if (tailMatch) {
    const octets = tailMatch[1].split('.').map(Number);
    if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    ipv4Tail = octets;
    s = s.slice(0, s.length - tailMatch[1].length); // keep the colon(s) before it
  }

  const dcolonCount = (s.match(/::/g) || []).length;
  if (dcolonCount > 1) return null;

  let groups;
  if (dcolonCount === 1) {
    const [left, right] = s.split('::');
    const leftParts = left ? left.split(':').filter(Boolean) : [];
    const rightParts = right ? right.split(':').filter(Boolean) : [];
    const explicitCount = leftParts.length + rightParts.length + (ipv4Tail ? 2 : 0);
    const missing = 8 - explicitCount;
    if (missing < 0) return null;
    groups = [
      ...leftParts.map((h) => parseInt(h, 16)),
      ...Array(missing).fill(0),
      ...rightParts.map((h) => parseInt(h, 16))
    ];
  } else {
    const parts = s ? s.split(':').filter(Boolean) : [];
    groups = parts.map((h) => parseInt(h, 16));
  }
  if (ipv4Tail) {
    groups.push(((ipv4Tail[0] << 8) | ipv4Tail[1]), ((ipv4Tail[2] << 8) | ipv4Tail[3]));
  }
  if (groups.length !== 8 || groups.some((g) => !Number.isInteger(g) || g < 0 || g > 0xffff)) return null;
  return groups;
}

// Numeric range check over the expanded 8-hextet form. Blocks: unspecified
// (::), loopback (::1), link-local (fe80::/10), unique-local (fc00::/7),
// and any IPv4-mapped/compatible/translated embedded address — decoded
// back to a dotted-quad and run through the SAME PRIVATE regex list every
// plain IPv4 host already goes through, rather than a separate special case.
function ipv6IsPrivate(groups) {
  if (groups.every((g) => g === 0)) return true; // ::
  if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 &&
      groups[4] === 0 && groups[5] === 0 && groups[6] === 0 && groups[7] === 1) return true; // ::1
  if ((groups[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((groups[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local (covers fd00:: too)
  // FIX ROUND 3, MINOR NEW-5: fec0::/10 deprecated IPv6 site-local. Same
  // mask width as link-local's /10 check above, different fixed prefix.
  if ((groups[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 site-local (deprecated)

  const toDottedQuad = (hi, lo) => [
    (hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff
  ].join('.');

  // IPv4-embedded forms all share a 64-bit zero prefix (groups 0-3), then
  // one of three known transition patterns in groups 4-5, with the IPv4
  // address packed into the final 32 bits (groups 6-7):
  //   ::a.b.c.d          (deprecated "compatible")  groups[4]=0,      groups[5]=0
  //   ::ffff:a.b.c.d     (mapped)                    groups[4]=0,      groups[5]=0xffff
  //   ::ffff:0:a.b.c.d   (a translated-address variant) groups[4]=0xffff, groups[5]=0
  const zeroPrefix = groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0;
  const g4 = groups[4], g5 = groups[5];
  const isEmbedded = zeroPrefix && (
    (g4 === 0 && g5 === 0) || (g4 === 0 && g5 === 0xffff) || (g4 === 0xffff && g5 === 0)
  );
  if (isEmbedded && PRIVATE.some((re) => re.test(toDottedQuad(groups[6], groups[7])))) return true;

  // FIX ROUND 3, MINOR NEW-5: two more transition mechanisms that embed an
  // IPv4 address, now cheap to add given the numeric form already exists.
  //   64:ff9b::a.b.c.d/96  NAT64 well-known prefix (RFC 6052): groups[0]=0x0064,
  //     groups[1]=0xff9b, groups[2..5]=0, IPv4 in groups[6..7].
  //   2002:WWXX:YYZZ::/16  6to4 (RFC 3056): groups[0]=0x2002, IPv4 packed
  //     directly into groups[1..2] (whatever follows is subnet/interface ID
  //     and doesn't change what address this literal reaches).
  const isNat64 = groups[0] === 0x0064 && groups[1] === 0xff9b &&
    groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0;
  if (isNat64 && PRIVATE.some((re) => re.test(toDottedQuad(groups[6], groups[7])))) return true;

  const isSixToFour = groups[0] === 0x2002;
  if (isSixToFour && PRIVATE.some((re) => re.test(toDottedQuad(groups[1], groups[2])))) return true;

  return false;
}

function isPrivateHost(host) {
  if (host.includes(':')) {
    const groups = expandIPv6(host);
    // Fail closed: url.hostname only ever hands us a colon-containing
    // string when it parsed as IPv6, so expandIPv6 should always succeed
    // here. If it somehow doesn't (a gap in this parser), refuse rather
    // than silently letting an unrecognised literal through.
    return groups ? ipv6IsPrivate(groups) : true;
  }
  return PRIVATE.some((re) => re.test(host));
}

export function validateTarget(urlString) {
  let url;
  try { url = new URL(urlString); }
  catch { return { ok: false, reason: 'not a valid URL' }; }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, reason: 'only http and https targets are allowed' };
  }
  let host = url.hostname.replace(/^\[|\]$/g, '');
  // FIX ROUND 2, CRITICAL 1 ("localhost."): WHATWG preserves a trailing DNS
  // root dot on non-IPv4 hosts. "localhost." still resolves to loopback on
  // typical resolvers but never matched /^localhost$/i. Strip a single
  // trailing dot before every check below.
  host = host.replace(/\.$/, '');
  if (isPrivateHost(host)) {
    return { ok: false, reason: 'private, loopback and link-local addresses are refused' };
  }
  return { ok: true, url };
}

// --- FIX ROUND 2, MINOR: AbortSignal.timeout fallback -------------------
// The round-1 code silently passed `signal: undefined` when
// AbortSignal.timeout was unavailable, which disables the timeout
// enforcement entirely with no indication anything is wrong. This provides
// a real, working fallback instead.
//
// FIX ROUND 3, IMPORTANT NEW-3: two bugs in that fallback. (1) It aborted
// with the message "timed out after Xms" — the catch-block classifier in
// probe() tests /abort|timeout/i, and "timed out" matches NEITHER word, so
// on any runtime lacking AbortSignal.timeout a genuine timeout was
// misreported as unreachableReason: 'dns'. Fixed by using the word
// "timeout" in the message. (2) The manual setTimeout was never cleared on
// success, leaving a dangling timer per probe. Fixed by returning a
// cancel() alongside the signal; probe() calls it once it's done with the
// signal, on every exit path.
export function timeoutSignal(ms) {
  if (typeof AbortSignal.timeout === 'function') {
    return { signal: AbortSignal.timeout(ms), cancel() {} };
  }
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(new Error(`timeout after ${ms}ms`)), ms);
  return { signal: controller.signal, cancel: () => clearTimeout(id) };
}

const empty = (reason, extra = {}) => ({
  ok: false, unreachableReason: reason, httpStatus: 0, headers: {},
  bodyText: '', body: null, parseError: null, truncated: false,
  finalUrl: null, ...extra
});

// --- FIX ROUND 2, IMPORTANT 1 + 3: bounded, streaming body read ---------
// The round-1 code did `await res.text()` then sliced — the entire body
// was buffered in memory before the cap was ever consulted, so a hostile
// endpoint streaming an unbounded response would be fully read (and could
// exhaust the isolate) regardless of MAX_BYTES. This reads the stream
// directly, counting real bytes (not res.text()'s UTF-16 code units —
// IMPORTANT 3), and cancels the source stream as soon as the cap is hit
// instead of continuing to pull from it.
// FIX ROUND 3, IMPORTANT NEW-1: even with byte-accurate INPUT capping,
// invalid UTF-8 can make the DECODED text re-encode to MORE than
// MAX_BYTES — TextDecoder's fatal:false mode emits one U+FFFD (3 bytes)
// per invalid byte, so up to MAX_BYTES invalid input bytes can decode to
// close to 3x MAX_BYTES of replacement characters. This decodes up to
// maxBytes of input without ever counting an unfinished trailing
// multi-byte sequence (same trick as the streaming path: incremental
// decode with no final flush silently drops a cut mid-character instead
// of replacing it), and is reused both by the fallback path and by the
// final output re-cap below.
function boundedDecode(bytes, maxBytes) {
  const decoder = new TextDecoder('utf-8', { fatal: false });
  let out = '';
  const limit = Math.min(bytes.length, maxBytes);
  for (let consumed = 0; consumed < limit;) {
    const take = Math.min(4096, limit - consumed);
    out += decoder.decode(bytes.subarray(consumed, consumed + take), { stream: true });
    consumed += take;
  }
  return out;
}

// Re-caps the OUTPUT text itself (not just the input bytes that produced
// it) so the cap's contract — "bodyText is at most MAX_BYTES bytes" — is
// actually true even for malformed UTF-8, not just for well-formed input.
function capOutputBytes(bodyText, truncatedSoFar) {
  const bytes = new TextEncoder().encode(bodyText);
  if (bytes.length <= MAX_BYTES) return { bodyText, truncated: truncatedSoFar };
  return { bodyText: boundedDecode(bytes, MAX_BYTES), truncated: true };
}

// FIX ROUND 3, MINOR NEW-4: guards a stream that spins via infinite
// zero-length chunks. Every REAL byte of content advances `total` and is
// bounded by MAX_BYTES already; this exists only for a chunk that
// contributes nothing, which the byte cap alone can never catch — without
// it such a stream would loop until the outer abort signal eventually
// fires, wasting up to a full TIMEOUT_MS of iteration. Generous relative
// to any realistic chunking of a MAX_BYTES response (which does not
// require anywhere near this many discrete reads in practice).
const MAX_CHUNKS = 20_000;

async function readCapped(res) {
  const body = res.body;
  if (!body || typeof body.getReader !== 'function') {
    // FIX ROUND 4, NEW-2b: round 3 argued this was unreachable for genuine
    // hostile content (a content-bearing Response always exposes .body)
    // and left a bounded-but-still-`await res.text()`-first fallback as
    // defense in depth. That made this path safe because of a belief about
    // the runtime, not safe by construction — if the assumption is ever
    // wrong (a non-conforming fetchImpl, an exotic runtime), it reverts to
    // unbounded buffering. Closed definitively instead of argued: a
    // response with no streamable .body has no meaningful content this
    // function can safely inspect, so it returns empty rather than ever
    // calling res.text(). There is no real case this loses — genuine
    // response content always arrives via .body (see the standalone test
    // proving that for a real Response), so nothing that mattered was
    // being read here anyway.
    return { bodyText: '', truncated: false };
  }

  const reader = body.getReader();
  // Decoding incrementally with { stream: true } — rather than
  // concatenating raw bytes and decoding once at the end — means a
  // truncation cut that lands in the middle of a multi-byte UTF-8
  // character is handled correctly: the decoder buffers the incomplete
  // trailing bytes internally and simply never emits them if we stop
  // without a final flush, instead of turning them into replacement
  // characters that would make the truncated text LARGER than the cap
  // once re-encoded.
  const decoder = new TextDecoder('utf-8', { fatal: false });
  let bodyText = '';
  let total = 0;
  let truncated = false;
  let chunkCount = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      bodyText += decoder.decode(); // flush: stream ended cleanly, nothing pending
      break;
    }
    chunkCount++;
    if (chunkCount > MAX_CHUNKS) {
      truncated = true;
      await reader.cancel().catch(() => {}); // stop pulling from a hostile source
      break;
    }
    if (value.length === 0) continue; // nothing to decode or count
    if (total + value.length > MAX_BYTES) {
      const remaining = MAX_BYTES - total;
      if (remaining > 0) bodyText += decoder.decode(value.subarray(0, remaining), { stream: true });
      truncated = true;
      await reader.cancel().catch(() => {}); // stop pulling from a hostile source
      break; // no final flush: drop any incomplete trailing bytes, don't invent replacement chars
    }
    bodyText += decoder.decode(value, { stream: true });
    total += value.length;
  }

  // Final safety net (IMPORTANT NEW-1): even though input bytes were
  // capped above, malformed UTF-8 in what we DID read can still have
  // inflated bodyText past MAX_BYTES via replacement characters.
  return capOutputBytes(bodyText, truncated);
}

export async function probe(urlString, fetchImpl = fetch) {
  // One shared timeout budget across the whole redirect chain, not one per
  // hop — otherwise a chain of slow hops could add up to far more than
  // TIMEOUT_MS of total latency.
  const { signal: timer, cancel: cancelTimer } = timeoutSignal(TIMEOUT_MS);
  try {
    let currentUrl = urlString;
    let res;

    for (let hop = 0; ; hop++) {
      if (hop > MAX_REDIRECTS) return empty('redirect_loop');

      // FIX ROUND 2, CRITICAL 2: validate every hop, including hop 0. Round 1
      // left the initial URL's validation entirely to the caller; any caller
      // that forgot to call validateTarget first disabled the guard for
      // exactly the attacker-supplied input this task exists to defend.
      // validateTarget is pure and idempotent, so re-running it here for
      // callers who already checked costs nothing.
      const v = validateTarget(currentUrl);
      if (!v.ok) return empty(hop === 0 ? 'blocked_initial' : 'blocked_redirect', { blockedReason: v.reason });

      try {
        res = await fetchImpl(currentUrl, {
          method: 'GET', redirect: 'manual', signal: timer,
          headers: { 'User-Agent': USER_AGENT }
        });
      } catch (e) {
        const msg = String(e && e.message || e);
        if (/abort|timeout/i.test(msg)) return empty('timeout');
        if (/redirect/i.test(msg)) return empty('redirect_loop');
        return empty('dns');
      }

      const isRedirect = res.status >= 300 && res.status < 400;
      const location = isRedirect ? res.headers.get('location') : null;
      if (!location) break;

      // FIX ROUND 2, IMPORTANT 2: resolving Location against the current URL
      // can throw (a malformed Location such as "http://[bad"). Round 1 left
      // this outside any try/catch, so it escaped probe() as an uncaught
      // TypeError instead of a Challenge. A hop that fails to resolve at all
      // is treated the same as a hop that resolves but fails validation.
      try {
        currentUrl = new URL(location, currentUrl).toString();
      } catch {
        return empty('blocked_redirect', { blockedReason: 'malformed Location header' });
      }
    }

    const headers = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

    // FIX ROUND 3, IMPORTANT NEW-2: readCapped() used to be a bare await —
    // a body stream that errors mid-read (connection reset, or this same
    // shared `timer` firing during the body read rather than the initial
    // fetch) rejected out of probe() as an unhandled promise instead of
    // returning a Challenge. Same defect class as the malformed-Location
    // fix above, on a different await; classified the same way.
    let capped;
    try {
      capped = await readCapped(res);
    } catch (e) {
      const msg = String(e && e.message || e);
      if (/abort|timeout/i.test(msg)) return empty('timeout');
      return empty('read_failed');
    }
    const { bodyText, truncated } = capped;

    let body = null, parseError = null;
    if (!truncated) {
      try { body = JSON.parse(bodyText); }
      catch (e) { parseError = String(e.message); }
    }

    return {
      ok: true, unreachableReason: null, httpStatus: res.status,
      headers, bodyText, body, parseError, truncated, finalUrl: currentUrl
    };
  } finally {
    // FIX ROUND 3, IMPORTANT NEW-3: clears the fallback's manual setTimeout
    // (a no-op when the native AbortSignal.timeout path was used) on every
    // exit from probe(), so a completed probe never leaves a dangling timer
    // behind.
    cancelTimer();
  }
}
