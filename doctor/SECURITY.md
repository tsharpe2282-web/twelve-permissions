# x402 Doctor — security posture and known residuals

This Worker fetches a URL supplied by an unauthenticated caller. That makes it
a potential SSRF vector and a fetch amplifier, so the guard and the limiter are
the two things to be careful with when changing anything here.

Written down because it was learned the expensive way: the first version of the
guard had five live bypasses that a passing test suite did not notice.

## What the guard does

`validateTarget()` in `src/probe.js` refuses, before any outbound fetch:

- non-`http(s)` schemes (`file:`, `gopher:`, `data:`, `ftp:`, …)
- loopback in every spelling the URL parser produces — `127.0.0.0/8`, `127.1`,
  `0.0.0.0`, `localhost`, `LocalHost.` (a trailing dot is stripped first)
- RFC1918 (`10/8`, `192.168/16`, `172.16–31`), CGNAT `100.64/10`,
  link-local `169.254/16`, and `255.255.255.255`
- IPv6 `::1`, `::`, `fe80::/10`, `fc00::/7`, `fec0::/10`
- **any** IPv4 embedded in IPv6 — mapped (`::ffff:127.0.0.1`), the hex form the
  parser normalises it to (`::ffff:7f00:1`), IPv4-compatible (`::127.0.0.1`),
  NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`)

The IPv6 handling **normalises to eight hextets and range-checks numerically**.
It does not pattern-match spellings. Do not "fix" a future bypass by adding
another regex for a new notation — that approach is what produced the original
five bypasses. Extend `expandIPv6`/`ipv6IsPrivate` instead.

`isPrivateHost` **fails closed**: when `expandIPv6` cannot parse a literal, the
host is treated as private and refused. Keep it that way.

Redirects are followed manually (`redirect: 'manual'`), capped at 3 hops, with
`Location` resolved against the current URL and the **full** guard re-run on
every hop before it is fetched. Verified live: Workers returns a real 3xx with a
readable `Location` here, not an opaque redirect.

## Known residuals — accepted, not fixed

**1. The guard is literal-only.** A DNS name that resolves into private space
(`localtest.me`, an internal hostname) passes `validateTarget`, because the
check runs on the hostname, not on the resolved address.

On Cloudflare Workers this is materially mitigated: subrequests egress from the
edge, RFC1918 and link-local are not routable from there, and there is no
Worker-reachable metadata service. **That is emergent platform behaviour, not a
documented guarantee.** It stops being true if this Worker ever gains a Tunnel
or Service binding to a private origin, or if `probe.js` is reused under Node —
which the test suite already does.

**2. DNS rebinding is unaddressed.** There is an unavoidable gap between
`validateTarget` resolving a name and `fetch` resolving it again.

Closing either properly needs resolve-then-pin, which the Workers runtime does
not currently expose.

## Rate limiting

`POST /probe` and the `probe_x402_endpoint` MCP tool share one bucket: 20/hour
per IP, 300/hour global. The thing being limited is the outbound amplification,
so **any new route or tool that can reach `probe()` must pass the same gate**.
Routes that perform no outbound fetch are deliberately ungated.

The limiter **fails open on a KV error** (a storage hiccup must not block a
legitimate caller) and **fails closed on a genuine over-limit** (429 +
`Retry-After`). Those two directions are easy to invert and inverting either one
is a real bug.

`RATE_LIMIT_KV` is a **dedicated namespace**. It is deliberately not the
`CLAIMS` namespace used by `hosting/`, which holds book-of-record claim state —
a public unauthenticated endpoint should not write into the same store.

It stores `rl:doctor:ip:<ip>:<window>`, a bare counter, TTL 2h. That is the
caller's IP, and the docs page says so. It does not store the probe target or
any payload. **If you change what is stored, change the footer in the same
commit** — an earlier draft advertised "nothing stored", which was false.
