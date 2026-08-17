import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateTarget, probe, MAX_REDIRECTS, MAX_BYTES, TIMEOUT_MS, timeoutSignal, USER_AGENT } from '../src/probe.js';

// FINAL FIX PASS, MINOR — a probed third party must be able to attribute the
// traffic, and bot-filtered targets 403 an unidentified client, which
// looksLikeX402 then reports as not_x402 for a genuinely working endpoint.
test('the outbound probe identifies itself with a User-Agent naming the tool and its URL', async () => {
  const seen = [];
  const fake = async (url, init) => {
    seen.push(init);
    return new Response('{"x402Version":1}', { status: 402 });
  };
  await probe('https://example.com/x', fake);
  assert.equal(seen.length, 1);
  const ua = seen[0].headers?.['User-Agent'] ?? seen[0].headers?.['user-agent'];
  assert.ok(ua, 'no User-Agent was sent');
  assert.match(ua, /x402-doctor/);
  assert.match(ua, /https?:\/\//, 'the UA must carry a URL a probed operator can look up');
  assert.equal(ua, USER_AGENT);
});

test('the User-Agent is sent on every redirect hop, not just the first', async () => {
  const uas = [];
  const fake = async (url, init) => {
    uas.push(init.headers['User-Agent']);
    if (url === 'https://example.com/x') {
      return new Response(null, { status: 302, headers: { location: 'https://example.com/y' } });
    }
    return new Response('{"x402Version":1}', { status: 402 });
  };
  await probe('https://example.com/x', fake);
  assert.equal(uas.length, 2);
  for (const ua of uas) assert.equal(ua, USER_AGENT);
});

test('accepts a normal https url', () => {
  assert.equal(validateTarget('https://example.com/paid').ok, true);
});

test('rejects non-http schemes', () => {
  for (const u of ['file:///etc/passwd', 'ftp://x.com', 'javascript:alert(1)']) {
    assert.equal(validateTarget(u).ok, false, u);
  }
});

test('rejects loopback and private addresses', () => {
  const blocked = [
    'http://127.0.0.1/x', 'http://localhost/x', 'http://[::1]/x',
    'http://10.0.0.5/x', 'http://192.168.1.1/x', 'http://172.16.0.1/x',
    'http://169.254.169.254/latest/meta-data'
  ];
  for (const u of blocked) assert.equal(validateTarget(u).ok, false, u);
});

test('a fetch that throws becomes unreachable, not healthy', async () => {
  const c = await probe('https://example.com/x', async () => { throw new Error('getaddrinfo ENOTFOUND'); });
  assert.equal(c.ok, false);
  assert.equal(c.unreachableReason, 'dns');
});

test('a 402 response is normalised into a Challenge', async () => {
  const fake = async () => new Response('{"x402Version":1}', {
    status: 402, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }
  });
  const c = await probe('https://example.com/x', fake);
  assert.equal(c.ok, true);
  assert.equal(c.httpStatus, 402);
  assert.equal(c.body.x402Version, 1);
  assert.equal(c.headers['cache-control'], 'no-store');
  assert.equal(c.parseError, null);
});

test('an unparseable body sets parseError and leaves body null', async () => {
  const fake = async () => new Response('<html>', { status: 402 });
  const c = await probe('https://example.com/x', fake);
  assert.equal(c.body, null);
  assert.ok(c.parseError);
});

// --- Additional SSRF bypass-shape coverage beyond the brief's literal cases ---

test('rejects data: scheme', () => {
  assert.equal(validateTarget('data:text/plain;base64,aGVsbG8=').ok, false);
});

test('rejects gopher: scheme', () => {
  assert.equal(validateTarget('gopher://127.0.0.1:70/x').ok, false);
});

test('rejects the shorthand loopback spelling 127.1', () => {
  assert.equal(validateTarget('http://127.1/x').ok, false);
});

test('rejects 0.0.0.0', () => {
  assert.equal(validateTarget('http://0.0.0.0/x').ok, false);
});

test('rejects the top of the 172.16/12 private range (172.31.x)', () => {
  assert.equal(validateTarget('http://172.31.255.255/x').ok, false);
});

test('accepts a public address just outside the 172.16/12 private range (172.32.x)', () => {
  assert.equal(validateTarget('http://172.32.0.1/x').ok, true);
});

// Embedded userinfo (user:pass@) does not let an attacker smuggle a
// private host past the guard: the WHATWG URL parser used here separates
// credentials from hostname correctly, so url.hostname is still the real
// target and the private-range check still applies to it.
test('rejects embedded credentials pointed at a private host (hostname parsing is not fooled by userinfo)', () => {
  assert.equal(validateTarget('http://user:pass@127.0.0.1/x').ok, false);
});

test('embedded credentials to a public host are not themselves blocked (not a private-network bypass)', () => {
  // Documented, not silently "fixed": the brief's guard only inspects
  // scheme + hostname, so this passes through. It is not an SSRF hole
  // because the request still only ever reaches the public host named
  // in the URL. See report for discussion.
  assert.equal(validateTarget('http://user:pass@example.com/x').ok, true);
});

// --- FIX ROUND 1, item 2: IPv4-mapped IPv6 addresses ---
// Originally found as an open gap: the WHATWG URL parser normalises
// decimal/hex/octal IPv4 encodings (e.g. "http://2130706433/x") to
// canonical dotted-decimal form BEFORE validateTarget's regexes ever run,
// so that class of trick is closed for free. But an IPv4-mapped IPv6
// literal such as "[::ffff:127.0.0.1]" normalises to "[::ffff:7f00:1]" —
// neither "::1" nor matched by any /^127\./-style regex. Per controller
// ruling, validateTarget now decodes the embedded IPv4 address (from
// either the dotted or hex-normalised form) and runs it through the same
// private-range logic, rather than special-casing loopback alone.
test('rejects IPv4-mapped IPv6 loopback, dotted form: [::ffff:127.0.0.1]', () => {
  assert.equal(validateTarget('http://[::ffff:127.0.0.1]/x').ok, false);
});

test('rejects IPv4-mapped IPv6 loopback, hex form the URL parser normalises to: [::ffff:7f00:1]', () => {
  assert.equal(validateTarget('http://[::ffff:7f00:1]/x').ok, false);
});

test('rejects IPv4-mapped IPv6 cloud metadata address: [::ffff:169.254.169.254]', () => {
  assert.equal(validateTarget('http://[::ffff:169.254.169.254]/x').ok, false);
});

test('rejects IPv4-mapped IPv6 RFC1918 address: [::ffff:10.0.0.1]', () => {
  assert.equal(validateTarget('http://[::ffff:10.0.0.1]/x').ok, false);
});

// FIX ROUND 3, MINOR: the original mixed-case header test lived here. It
// built its fake response from a real `new Response(..., { headers })`,
// but a real Headers object always lowercases its keys on construction —
// so that test passed even with probe.js's `.toLowerCase()` call deleted,
// and was misleading about what it covered. Deleted; the real replacement
// (which drives probe() from a fake response whose headers.forEach yields
// literal mixed-case keys, and so CAN fail if normalization is removed)
// lives in the FIX ROUND 2 section below.

// --- Timeout and size cap enforcement ---

test('probe enforces a byte cap and marks the body truncated', async () => {
  const big = 'x'.repeat(300 * 1024);
  const fake = async () => new Response(big, { status: 402 });
  const c = await probe('https://example.com/x', fake);
  assert.equal(c.truncated, true);
  assert.equal(c.body, null);
});

test('a fetch that aborts (timeout) is reported as unreachable with reason timeout', async () => {
  const fake = async () => {
    const err = new Error('The operation was aborted');
    err.name = 'AbortError';
    throw err;
  };
  const c = await probe('https://example.com/x', fake);
  assert.equal(c.ok, false);
  assert.equal(c.unreachableReason, 'timeout');
});

test('a fetch that throws with a redirect-shaped message is reported as unreachable with reason redirect_loop', async () => {
  const fake = async () => { throw new Error('redirect count exceeded'); };
  const c = await probe('https://example.com/x', fake);
  assert.equal(c.ok, false);
  assert.equal(c.unreachableReason, 'redirect_loop');
});

// --- FIX ROUND 1, item 1: the redirect hole ---
// Originally found as an open gap: probe() called fetchImpl with
// { redirect: 'follow' } and never inspected the final response's URL or
// re-ran validateTarget on any hop, so a URL that passed the initial guard
// public could 30x internally to a private/metadata address and be
// followed transparently.
//
// Per controller ruling this is fixed by DEVIATING from the brief:
// fetchImpl is now called with { redirect: 'manual' }, and probe() follows
// redirects itself, capped at MAX_REDIRECTS hops, validating each
// Location (resolved against the current URL, since it may be relative)
// with the full validateTarget guard before ever fetching it. This is a
// deliberate departure from task-7-brief.md's literal `redirect: 'follow'`
// — the brief's authors did not intend to leave this hole open; the fix
// closes it without turning healthy redirecting endpoints into false
// failures (see the "still works" cases below).

test('a public URL that redirects to the cloud metadata address is blocked, not followed', async () => {
  const fake = async (url) => {
    if (url === 'https://public.example.com/x') {
      return new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/latest/meta-data' } });
    }
    throw new Error('must not fetch a redirect target that fails validation: ' + url);
  };
  const c = await probe('https://public.example.com/x', fake);
  assert.equal(c.ok, false);
  assert.equal(c.unreachableReason, 'blocked_redirect');
});

test('a public URL that redirects to loopback is blocked, not followed', async () => {
  const fake = async (url) => {
    if (url === 'https://public.example.com/x') {
      return new Response(null, { status: 302, headers: { location: 'http://127.0.0.1/admin' } });
    }
    throw new Error('must not fetch a redirect target that fails validation: ' + url);
  };
  const c = await probe('https://public.example.com/x', fake);
  assert.equal(c.ok, false);
  assert.equal(c.unreachableReason, 'blocked_redirect');
});

test('a relative Location redirect that stays public still succeeds (not a false block)', async () => {
  const fake = async (url) => {
    if (url === 'https://public.example.com/x402') {
      return new Response(null, { status: 301, headers: { location: '/x402/' } });
    }
    if (url === 'https://public.example.com/x402/') {
      return new Response('{"x402Version":1}', { status: 402 });
    }
    throw new Error('unexpected url ' + url);
  };
  const c = await probe('https://public.example.com/x402', fake);
  assert.equal(c.ok, true);
  assert.equal(c.httpStatus, 402);
  assert.equal(c.finalUrl, 'https://public.example.com/x402/');
});

test('a normal http to https redirect still succeeds (not a false block)', async () => {
  const fake = async (url) => {
    if (url === 'http://example.com/x') {
      return new Response(null, { status: 301, headers: { location: 'https://example.com/x' } });
    }
    if (url === 'https://example.com/x') {
      return new Response('{"x402Version":1}', { status: 402 });
    }
    throw new Error('unexpected url ' + url);
  };
  const c = await probe('http://example.com/x', fake);
  assert.equal(c.ok, true);
  assert.equal(c.httpStatus, 402);
  assert.equal(c.finalUrl, 'https://example.com/x');
});

test('a redirect chain within the hop cap that lands public still succeeds (not a false block)', async () => {
  const chain = [
    'https://a.example.com/1',
    'https://a.example.com/2',
    'https://a.example.com/3',
    'https://a.example.com/final'
  ];
  assert.equal(chain.length - 1, MAX_REDIRECTS); // exactly at the cap: 3 redirects
  const fake = async (url) => {
    const i = chain.indexOf(url);
    if (i === -1) throw new Error('unexpected url ' + url);
    if (i < chain.length - 1) return new Response(null, { status: 302, headers: { location: chain[i + 1] } });
    return new Response('{"x402Version":1}', { status: 402 });
  };
  const c = await probe(chain[0], fake);
  assert.equal(c.ok, true);
  assert.equal(c.httpStatus, 402);
  assert.equal(c.finalUrl, chain[chain.length - 1]);
});

test('a redirect chain exceeding the hop cap fails cleanly and does not keep following', async () => {
  let fetchCount = 0;
  const fake = async (url) => {
    fetchCount++;
    return new Response(null, { status: 302, headers: { location: url + '+' } });
  };
  const c = await probe('https://a.example.com/0', fake);
  assert.equal(c.ok, false);
  assert.equal(c.unreachableReason, 'redirect_loop');
  assert.equal(fetchCount, MAX_REDIRECTS + 1); // stops after the cap; never fetches a 5th hop
});

// =====================================================================
// FIX ROUND 2 — security review re-derivation. Five validateTarget
// bypasses, hop-0 unvalidated inside probe(), unbounded body buffering,
// an uncaught throw on a malformed Location, and byte-vs-UTF16 miscount.
// =====================================================================

// --- CRITICAL 1: five validateTarget bypasses ---
// Fixed by normalising ANY IPv6 literal to its full 8-hextet numeric form
// and range-checking numerically (loopback/unspecified/link-local/ULA, and
// any IPv4-mapped/compatible embedded address run through the SAME
// PRIVATE regex list already used for plain dotted-quad hosts) — not by
// adding more spelling-specific string patterns.

test('rejects "localhost." — WHATWG preserves the trailing DNS root dot on non-IP hosts, and it still resolves to loopback', () => {
  assert.equal(validateTarget('http://LocalHost./x').ok, false);
});

test('rejects IPv6 link-local [fe80::1] (fe80::/10)', () => {
  assert.equal(validateTarget('http://[fe80::1]/x').ok, false);
});

test('rejects IPv6 unique-local [fc00::] (fc00::/7)', () => {
  assert.equal(validateTarget('http://[fc00::]/x').ok, false);
});

test('rejects IPv6 unique-local [fd00::] (also within fc00::/7)', () => {
  assert.equal(validateTarget('http://[fd00::]/x').ok, false);
});

test('rejects IPv6 unspecified address [::]', () => {
  assert.equal(validateTarget('http://[::]/x').ok, false);
});

test('rejects IPv4-compatible IPv6 loopback [::127.0.0.1] (normalises to [::7f00:1])', () => {
  assert.equal(validateTarget('http://[::127.0.0.1]/x').ok, false);
});

test('rejects the extra-hextet mapped form [::ffff:0:127.0.0.1] (normalises to [::ffff:0:7f00:1]) — a second spelling the old exactly-2-hextet regex missed', () => {
  assert.equal(validateTarget('http://[::ffff:0:127.0.0.1]/x').ok, false);
});

test('a genuine public IPv6 address is NOT blocked (negative control on the new numeric range check)', () => {
  assert.equal(validateTarget('http://[2001:db8::1]/x').ok, true);
});

// --- CRITICAL 2: hop 0 must be validated inside probe() itself ---
test('probe() refuses a private initial URL on its own, with no caller-side validateTarget call', async () => {
  const fake = async () => { throw new Error('must not fetch a private initial URL at all'); };
  const c = await probe('http://127.0.0.1/admin', fake);
  assert.equal(c.ok, false);
  assert.equal(c.unreachableReason, 'blocked_initial');
});

// --- IMPORTANT 1 + 3: the size cap must bound bytes actually read off the
// wire (not buffer-then-slice), and must count real bytes, not UTF-16
// code units. Proven two ways: (a) a hostile infinite stream is stopped
// early rather than being pulled to completion, and (b) multibyte content
// whose UTF-16 length would UNDER-report its true byte size still trips
// truncation at the real byte boundary.

test('a hostile endpoint streaming far more than MAX_BYTES is stopped early, not fully buffered', async () => {
  const chunkSize = 64 * 1024;
  // FIX ROUND 3, MINOR: this used to be truly infinite, which means a
  // regression that deletes the cap would make this test HANG the suite
  // forever instead of failing. A test that fails by hanging is a bad
  // signal in CI. HANG_GUARD makes the source stream finite (far above
  // where the real cap should kick in) purely as a hang backstop.
  //
  // FIX ROUND 4, item 3: HANG_GUARD and the "did the cap actually work"
  // assertion are two different jobs and were wrongly conflated in round
  // 3 — asserting only pullCount < HANG_GUARD (200) meant a cap that was
  // 10x too loose (e.g. one that let through ~40 chunks / 2.5MB instead of
  // ~4 chunks / 256KB) would still pass. Decoupled: HANG_GUARD stays large
  // as a pure safety net so a fully-deleted cap fails fast instead of
  // hanging; a separate, TIGHT expected-pull-count assertion (cap ÷ chunk
  // size, plus a small margin for Response's internal read-ahead) catches
  // a partial regression too.
  const HANG_GUARD = 200;
  const EXPECTED_MAX_PULLS = Math.ceil(MAX_BYTES / chunkSize) + 3; // 4 + margin
  let pullCount = 0;
  let cancelled = false;
  const stream = new ReadableStream({
    pull(controller) {
      pullCount++;
      if (pullCount > HANG_GUARD) { controller.close(); return; }
      controller.enqueue(new Uint8Array(chunkSize).fill(65)); // a hostile, effectively-unbounded body
    },
    cancel() { cancelled = true; }
  });
  const fake = async () => new Response(stream, { status: 402 });
  const c = await probe('https://example.com/x', fake);
  assert.equal(c.truncated, true);
  assert.ok(pullCount <= EXPECTED_MAX_PULLS,
    `expected at most ${EXPECTED_MAX_PULLS} pulls (MAX_BYTES / chunkSize + margin), but pulled ${pullCount} — the cap may be too loose`);
  assert.ok(cancelled, 'the source stream should be cancelled once the cap is reached');
});

test('the byte cap counts real UTF-8 bytes, not UTF-16 code units (multibyte content)', async () => {
  // '€' is 1 UTF-16 code unit but 3 UTF-8 bytes. A body of exactly
  // MAX_BYTES such characters has a JS string .length of MAX_BYTES (which
  // the OLD raw.length check would have accepted as "not truncated") but
  // an actual byte size of 3 * MAX_BYTES — well over the cap.
  const big = '€'.repeat(MAX_BYTES);
  const fake = async () => new Response(big, { status: 402 });
  const c = await probe('https://example.com/x', fake);
  assert.equal(c.truncated, true);
  const actualBytes = new TextEncoder().encode(c.bodyText).length;
  assert.ok(actualBytes <= MAX_BYTES, `kept ${actualBytes} bytes, cap is ${MAX_BYTES}`);
});

// --- IMPORTANT 2: a malformed Location must not throw out of probe() ---
test('a malformed redirect Location does not throw; probe() returns a blocked-redirect Challenge', async () => {
  const fake = async (url) => {
    if (url === 'https://public.example.com/x') {
      return new Response(null, { status: 302, headers: { location: 'http://[bad' } });
    }
    throw new Error('must not fetch: ' + url);
  };
  const c = await probe('https://public.example.com/x', fake);
  assert.equal(c.ok, false);
  assert.equal(c.unreachableReason, 'blocked_redirect');
});

// --- MINOR: lock in the two reviewer-verified redirect blocks ---
test('a redirect Location of file:///etc/passwd is blocked, not followed', async () => {
  const fake = async (url) => {
    if (url === 'https://public.example.com/x') {
      return new Response(null, { status: 302, headers: { location: 'file:///etc/passwd' } });
    }
    throw new Error('must not fetch: ' + url);
  };
  const c = await probe('https://public.example.com/x', fake);
  assert.equal(c.ok, false);
  assert.equal(c.unreachableReason, 'blocked_redirect');
});

test('a protocol-relative redirect Location to a private host is blocked, not followed', async () => {
  const fake = async (url) => {
    if (url === 'https://public.example.com/x') {
      return new Response(null, { status: 302, headers: { location: '//127.0.0.1/y' } });
    }
    throw new Error('must not fetch: ' + url);
  };
  const c = await probe('https://public.example.com/x', fake);
  assert.equal(c.ok, false);
  assert.equal(c.unreachableReason, 'blocked_redirect');
});

// --- MINOR: the mixed-case header test rewritten to actually prove the
// PROBE's own normalization. A real Headers object always lowercases its
// keys on construction, so a test built from `new Response(..., {headers})`
// cannot fail even if probe.js's `.toLowerCase()` call is deleted. This
// version drives probe() from a fake response whose headers.forEach
// yields mixed-case keys directly, which only a real normalization step
// in probe.js can survive.
test("probe's own header normalization lowercases mixed-case keys (proven with a fake response Headers cannot itself lowercase for us)", async () => {
  const fakeRes = {
    status: 402,
    headers: {
      forEach(cb) {
        cb('application/json', 'Content-Type');
        cb('no-store', 'Cache-Control');
      },
      get() { return null; }
    },
    body: null,
    text: async () => '{"x402Version":1}'
  };
  const fake = async () => fakeRes;
  const c = await probe('https://example.com/x', fake);
  assert.equal(c.headers['cache-control'], 'no-store');
  assert.equal(c.headers['content-type'], 'application/json');
});

// --- MINOR: AbortSignal.timeout must have a real fallback, not silently
// disable the timeout when unavailable.
// FIX ROUND 3, IMPORTANT NEW-3: timeoutSignal's return shape changed from a
// bare signal to { signal, cancel } so the fallback's setTimeout can be
// cleared once the operation it was guarding finishes (see the dangling-
// timer tests further down). Updated here to match.
test('timeoutSignal provides a working fallback when AbortSignal.timeout is unavailable', async () => {
  const original = AbortSignal.timeout;
  AbortSignal.timeout = undefined; // simulate a runtime lacking it
  try {
    const { signal } = timeoutSignal(20);
    assert.equal(signal.aborted, false);
    await new Promise((resolve) => setTimeout(resolve, 60));
    assert.equal(signal.aborted, true);
  } finally {
    AbortSignal.timeout = original;
  }
});

// --- Re-confirm the legitimate-redirect cases are unaffected by this round ---
test('RE-CONFIRM: a relative Location redirect that stays public still succeeds after round 2', async () => {
  const fake = async (url) => {
    if (url === 'https://public.example.com/x402') {
      return new Response(null, { status: 301, headers: { location: '/x402/' } });
    }
    if (url === 'https://public.example.com/x402/') {
      return new Response('{"x402Version":1}', { status: 402 });
    }
    throw new Error('unexpected url ' + url);
  };
  const c = await probe('https://public.example.com/x402', fake);
  assert.equal(c.ok, true);
  assert.equal(c.httpStatus, 402);
});

test('RE-CONFIRM: a normal http to https redirect still succeeds after round 2', async () => {
  const fake = async (url) => {
    if (url === 'http://example.com/x') {
      return new Response(null, { status: 301, headers: { location: 'https://example.com/x' } });
    }
    if (url === 'https://example.com/x') {
      return new Response('{"x402Version":1}', { status: 402 });
    }
    throw new Error('unexpected url ' + url);
  };
  const c = await probe('http://example.com/x', fake);
  assert.equal(c.ok, true);
  assert.equal(c.httpStatus, 402);
});

test('RE-CONFIRM: a redirect chain within the hop cap still succeeds after round 2', async () => {
  const chain = [
    'https://a.example.com/1', 'https://a.example.com/2',
    'https://a.example.com/3', 'https://a.example.com/final'
  ];
  const fake = async (url) => {
    const i = chain.indexOf(url);
    if (i === -1) throw new Error('unexpected url ' + url);
    if (i < chain.length - 1) return new Response(null, { status: 302, headers: { location: chain[i + 1] } });
    return new Response('{"x402Version":1}', { status: 402 });
  };
  const c = await probe(chain[0], fake);
  assert.equal(c.ok, true);
  assert.equal(c.httpStatus, 402);
});

// =====================================================================
// FIX ROUND 3 — a re-review of the round-2 fixes themselves: two new
// unhandled-rejection paths introduced by those fixes, a misreported
// timeout reason, invalid-UTF-8 cap inflation, a zero-length-chunk spin,
// and cheap additional IPv6/IPv4 coverage now that the numeric form exists.
// =====================================================================

// --- IMPORTANT NEW-2: readCapped()'s rejection used to escape probe() ---
// A body stream that errors mid-read (connection reset, or the shared
// abort signal firing during the body read rather than during the initial
// fetch) used to reject out of probe() as an unhandled promise instead of
// returning a Challenge — the same defect class as round 2's malformed-
// Location fix, on a different await.
test('a body read that fails mid-stream (connection reset) does not throw out of probe()', async () => {
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array([1, 2, 3]));
    },
    pull() {
      throw new Error('ECONNRESET');
    }
  });
  const fake = async () => new Response(stream, { status: 402 });
  const c = await probe('https://example.com/x', fake);
  assert.equal(c.ok, false);
  assert.equal(c.unreachableReason, 'read_failed');
});

test('a body read that fails because the shared timeout fires mid-read is reported as timeout, not read_failed', async () => {
  const stream = new ReadableStream({
    pull() {
      const err = new Error('The operation was aborted');
      err.name = 'AbortError';
      throw err;
    }
  });
  const fake = async () => new Response(stream, { status: 402 });
  const c = await probe('https://example.com/x', fake);
  assert.equal(c.ok, false);
  assert.equal(c.unreachableReason, 'timeout');
});

// --- FIX ROUND 4, item 1 (was IMPORTANT NEW-2b): the no-stream case in
// readCapped no longer calls res.text() at all — round 3 left a bounded
// but still `await res.text()`-first fallback, resting on the belief that
// a genuine hostile body always arrives with a streamable .body. That
// belief was correct, but it meant safety depended on an assumption about
// the runtime rather than the code's own structure. Removed the
// assumption and the unbounded read together: no .body means nothing is
// read, full stop.
test('a response with no streamable .body never calls .text() and returns an empty body, not an unbounded read', async () => {
  let textWasCalled = false;
  const fakeRes = {
    status: 402,
    headers: { forEach() {}, get: () => null },
    body: null,
    text: async () => { textWasCalled = true; return 'x'.repeat(10 * 1024 * 1024); } // must never run
  };
  const fake = async () => fakeRes;
  const c = await probe('https://example.com/x', fake);
  assert.equal(textWasCalled, false, 'readCapped must not call res.text() when res.body is absent');
  assert.equal(c.bodyText, '');
  assert.equal(c.truncated, false);
});

// This still holds and remains useful context (it's why the case above is
// the only way to reach the no-.body branch from a real fetch response),
// but it is no longer what makes NEW-2b safe — the branch above is safe by
// construction now, regardless of whether this stays true on every runtime.
test('a real Response with content always exposes a streamable .body', () => {
  const r = new Response('x'.repeat(10), { status: 200 });
  assert.equal(typeof r.body?.getReader, 'function');
});

// --- IMPORTANT NEW-3: the fallback timeout must be reported as a timeout ---
// timeoutSignal's manual fallback used to abort with the message
// "timed out after ${ms}ms", which the classifier's /abort|timeout/i test
// does NOT match ("timed out" contains neither literal word). On any
// runtime without AbortSignal.timeout, a genuine timeout was silently
// misreported as a DNS failure — exactly the kind of wrong diagnosis this
// tool exists to prevent.
test('timeoutSignal fallback aborts with a message the probe classifier recognises as a timeout', async () => {
  const original = AbortSignal.timeout;
  AbortSignal.timeout = undefined;
  try {
    const { signal } = timeoutSignal(20);
    await new Promise((resolve) => setTimeout(resolve, 60));
    assert.equal(signal.aborted, true);
    const reasonMessage = String((signal.reason && signal.reason.message) || signal.reason);
    assert.match(reasonMessage, /abort|timeout/i);
  } finally {
    AbortSignal.timeout = original;
  }
});

test('a fetchImpl rejecting with the fallback timeoutSignal error shape is classified as timeout, not dns', async () => {
  // Exercises probe()'s classifier against the EXACT error shape
  // timeoutSignal's fallback produces, without waiting a real TIMEOUT_MS
  // (10s) for the full end-to-end path.
  const fallbackTimeoutError = new Error(`timeout after ${TIMEOUT_MS}ms`);
  const fake = async () => { throw fallbackTimeoutError; };
  const c = await probe('https://example.com/x', fake);
  assert.equal(c.ok, false);
  assert.equal(c.unreachableReason, 'timeout');
});

test('timeoutSignal fallback cancel() prevents a dangling timer from firing after success', async () => {
  const original = AbortSignal.timeout;
  AbortSignal.timeout = undefined;
  try {
    const { signal, cancel } = timeoutSignal(20);
    cancel(); // simulates probe() clearing it once the operation finished
    await new Promise((resolve) => setTimeout(resolve, 60));
    assert.equal(signal.aborted, false, 'a cancelled fallback timer must never fire');
  } finally {
    AbortSignal.timeout = original;
  }
});

// FIX ROUND 4, item 2: the previous version of this test only asserted
// c.ok === true, which proves nothing about the timer — it would pass
// identically with cancelTimer() deleted from probe(). This version spies
// on the real global setTimeout/clearTimeout to observe the actual id
// timeoutSignal's fallback schedules, and asserts probe() clears that
// EXACT id before returning. Deleting cancelTimer() from probe() makes
// this test fail (the scheduled id is never cleared).
test('probe() clears its fallback timeout timer on a normal successful response (no dangling timer)', async () => {
  const originalAbortTimeout = AbortSignal.timeout;
  const originalSetTimeout = global.setTimeout;
  const originalClearTimeout = global.clearTimeout;
  AbortSignal.timeout = undefined; // force the manual fallback for this probe() call

  const scheduledIds = [];
  const clearedIds = [];
  global.setTimeout = (fn, ms, ...args) => {
    const id = originalSetTimeout(fn, ms, ...args);
    scheduledIds.push(id);
    return id;
  };
  global.clearTimeout = (id) => {
    clearedIds.push(id);
    return originalClearTimeout(id);
  };

  try {
    const fake = async () => new Response('{"x402Version":1}', { status: 402 });
    const c = await probe('https://example.com/x', fake);
    assert.equal(c.ok, true);
    assert.equal(scheduledIds.length, 1, 'expected exactly one fallback timer to be scheduled');
    assert.ok(clearedIds.includes(scheduledIds[0]),
      'expected probe() to clear the exact fallback timer id it scheduled');
  } finally {
    AbortSignal.timeout = originalAbortTimeout;
    global.setTimeout = originalSetTimeout;
    global.clearTimeout = originalClearTimeout;
  }
});

// --- IMPORTANT NEW-1: invalid UTF-8 must not inflate bodyText past the cap ---
// TextDecoder('utf-8', { fatal: false }) emits one U+FFFD (3 bytes) per
// invalid byte. MAX_BYTES invalid bytes therefore used to decode into a
// bodyText that re-encodes to roughly 3x MAX_BYTES — the cap's contract
// ("bodyText is at most MAX_BYTES bytes") was false for malformed input.
test('invalid UTF-8 bytes do not inflate bodyText past MAX_BYTES once re-encoded', async () => {
  const bad = new Uint8Array(MAX_BYTES).fill(0xff); // 0xFF is invalid in every UTF-8 position
  const fake = async () => new Response(bad, { status: 402 });
  const c = await probe('https://example.com/x', fake);
  assert.equal(c.truncated, true);
  const actualBytes = new TextEncoder().encode(c.bodyText).length;
  assert.ok(actualBytes <= MAX_BYTES,
    `kept ${actualBytes} bytes (inflated via U+FFFD replacement characters?), cap is ${MAX_BYTES}`);
});

// --- MINOR NEW-4: a stream of infinite zero-length chunks must not spin ---
// The read loop advanced `total` only by value.length, so a stream that
// enqueues endless empty Uint8Arrays never trips the byte cap and would
// loop until the outer abort signal eventually fired (up to TIMEOUT_MS of
// wasted iteration).
test('a stream of infinite zero-length chunks is stopped by an iteration cap, not spun forever', async () => {
  const HANG_GUARD = 200_000; // bounded so a broken/missing cap fails fast, not hangs
  let pullCount = 0;
  let cancelled = false;
  const stream = new ReadableStream({
    pull(controller) {
      pullCount++;
      if (pullCount > HANG_GUARD) { controller.close(); return; }
      controller.enqueue(new Uint8Array(0)); // contributes zero bytes, forever
    },
    cancel() { cancelled = true; }
  });
  const fake = async () => new Response(stream, { status: 402 });
  const c = await probe('https://example.com/x', fake);
  assert.equal(c.truncated, true);
  assert.ok(pullCount < HANG_GUARD,
    `expected the iteration cap to stop pulling, but pulled ${pullCount} times (hit the hang-guard)`);
  assert.ok(cancelled, 'the source stream should be cancelled once the iteration cap is reached');
});

// --- MINOR NEW-5: cheap additional IPv6 spellings now that the numeric
// form exists, plus two missing IPv4 ranges ---

test('rejects NAT64-embedded loopback: 64:ff9b::7f00:1 (RFC 6052 well-known prefix, encodes 127.0.0.1)', () => {
  assert.equal(validateTarget('http://[64:ff9b::7f00:1]/x').ok, false);
});

test('rejects 6to4-embedded loopback: 2002:7f00:1:: (RFC 3056, encodes 127.0.0.1)', () => {
  assert.equal(validateTarget('http://[2002:7f00:1::]/x').ok, false);
});

test('rejects IPv6 deprecated site-local [fec0::1] (fec0::/10)', () => {
  assert.equal(validateTarget('http://[fec0::1]/x').ok, false);
});

test('rejects CGNAT address 100.64.0.1 (100.64.0.0/10, RFC 6598)', () => {
  assert.equal(validateTarget('http://100.64.0.1/x').ok, false);
});

test('rejects CGNAT boundary 100.127.255.255 (top of 100.64.0.0/10)', () => {
  assert.equal(validateTarget('http://100.127.255.255/x').ok, false);
});

test('accepts a public address just outside the CGNAT range: 100.128.0.1', () => {
  assert.equal(validateTarget('http://100.128.0.1/x').ok, true);
});

test('accepts a public address just below the CGNAT range: 100.63.255.255', () => {
  assert.equal(validateTarget('http://100.63.255.255/x').ok, true);
});

test('rejects the broadcast address 255.255.255.255', () => {
  assert.equal(validateTarget('http://255.255.255.255/x').ok, false);
});

// --- Re-confirm the legitimate-redirect cases are still unaffected after round 3 ---
test('RE-CONFIRM: a relative Location redirect that stays public still succeeds after round 3', async () => {
  const fake = async (url) => {
    if (url === 'https://public.example.com/x402') {
      return new Response(null, { status: 301, headers: { location: '/x402/' } });
    }
    if (url === 'https://public.example.com/x402/') {
      return new Response('{"x402Version":1}', { status: 402 });
    }
    throw new Error('unexpected url ' + url);
  };
  const c = await probe('https://public.example.com/x402', fake);
  assert.equal(c.ok, true);
  assert.equal(c.httpStatus, 402);
});

test('RE-CONFIRM: a normal http to https redirect still succeeds after round 3', async () => {
  const fake = async (url) => {
    if (url === 'http://example.com/x') {
      return new Response(null, { status: 301, headers: { location: 'https://example.com/x' } });
    }
    if (url === 'https://example.com/x') {
      return new Response('{"x402Version":1}', { status: 402 });
    }
    throw new Error('unexpected url ' + url);
  };
  const c = await probe('http://example.com/x', fake);
  assert.equal(c.ok, true);
  assert.equal(c.httpStatus, 402);
});

test('RE-CONFIRM: a redirect chain within the hop cap still succeeds after round 3', async () => {
  const chain = [
    'https://a.example.com/1', 'https://a.example.com/2',
    'https://a.example.com/3', 'https://a.example.com/final'
  ];
  const fake = async (url) => {
    const i = chain.indexOf(url);
    if (i === -1) throw new Error('unexpected url ' + url);
    if (i < chain.length - 1) return new Response(null, { status: 302, headers: { location: chain[i + 1] } });
    return new Response('{"x402Version":1}', { status: 402 });
  };
  const c = await probe(chain[0], fake);
  assert.equal(c.ok, true);
  assert.equal(c.httpStatus, 402);
});
