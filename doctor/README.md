# x402 Doctor

A free diagnostic for **x402 seller endpoints**. Point it at your paid endpoint
and it performs the handshake a paying client would — a `GET` with no
`X-PAYMENT` header — then reports what is wrong with the 402 challenge you
answered with, and what to change.

**Live: https://x402-doctor.tsharpe.workers.dev**

```bash
curl -s -X POST https://x402-doctor.tsharpe.workers.dev/probe \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://your-service.example/paid-endpoint"}'
```

## Why seller-side

Buyer-side x402 is well served by the official SDKs. Seller-side is where people
get stuck, because the failure happens inside a facilitator you cannot see into:
your endpoint looks fine, the payment does not settle, and the error surfaces
somewhere you do not control.

Every check carries a `provenance` field, so no finding has to be taken on
trust:

- **`spec`** — the x402 specification requires it.
- **`observed (source)`** — we watched a real facilitator reject it, and the
  source is named.

## What you get back

```json
{
  "target": "https://your-service.example/paid-endpoint",
  "finalUrl": "https://your-service.example/paid-endpoint",
  "status": "advisories",
  "http": { "status": 402, "contentType": "application/json" },
  "findings": [
    {
      "id": "challenge-cacheable",
      "severity": "warn",
      "title": "402 challenge is cacheable",
      "why": "…",
      "fix": "…",
      "provenance": "observed (ours, 2026-08-15)",
      "evidence": "cache-control: public, max-age=300"
    }
  ],
  "checksRun": 16,
  "bodyTruncated": false,
  "bodyChecksSkipped": 0,
  "bodySkipReason": null
}
```

`status` is one of:

| status | meaning |
|---|---|
| `healthy` | nothing to report |
| `advisories` | notes worth reading, but no errors |
| `defects_found` | at least one `error` |
| `not_x402` | the endpoint did not answer with an x402 challenge |
| `unreachable` | the probe could not complete — see `reason` |

If the body was truncated or unparseable, body checks are skipped and the report
**says so** (`bodyChecksSkipped`, `bodySkipReason`). A check that did not run is
never reported as a check that passed.

## The 16 checks

| id | severity | check | provenance |
|---|---|---|---|
| `no-402` | error | Endpoint did not answer 402 without payment | spec |
| `body-not-json` | error | 402 body is not parseable JSON | spec |
| `oversized-body` | warn | 402 body exceeded the read cap | observed (this probe) |
| `missing-x402-version` | error | x402Version is absent or not 1 | spec |
| `accepts-empty` | error | accepts is missing, not an array, or empty | spec |
| `output-schema-null` | error | outputSchema is explicitly null | observed (Coinbase CDP facilitator, 2026-07-17) |
| `amount-not-atomic-string` | error | maxAmountRequired is not an atomic-unit string | spec |
| `asset-network-mismatch` | warn | asset is not the USDC contract for this network | spec |
| `missing-eip712-extra` | error | scheme "exact" without the EIP-712 domain in extra | spec |
| `unknown-network-name` | info | network name is not one this probe recognises | spec |
| `payto-not-an-address` | error | payTo is not a valid address for this network | spec |
| `payto-not-checksummed` | info | payTo is not a checksummed address | spec |
| `no-timeout-declared` | info | maxTimeoutSeconds is absent | spec |
| `challenge-cacheable` | warn | 402 challenge is cacheable | observed (ours, 2026-08-15) |
| `cors-headers-not-exposed` | info | browser clients will need payment headers exposed on the settlement response | observed (x402-foundation/x402#2112) |
| `bazaar-ext-inside-accepts` | warn | Bazaar extension declared inside an accepts entry | observed (ours, 2026-08-14) |

## Also an MCP server

`POST /mcp`, stateless Streamable HTTP. Three tools:

| tool | what it does |
|---|---|
| `probe_x402_endpoint` | run the diagnostic against a URL |
| `explain_defect` | full explanation of one check by id |
| `list_checks` | the whole rule table with provenance |

## What it deliberately does not do

- **It never validates through a facilitator.** Doing so would route your
  traffic through someone else's facilitator credentials. Every check here is
  derived from the challenge you actually returned.
- **It never sends a payment**, and never asks for a key, a seed, or a wallet.
- **It does not judge networks it does not know.** An unrecognised network name
  is an `info` note about the limits of this probe's list — not a claim that
  your network is wrong. Address-format rules apply only where the address
  format is known.

## Limits worth knowing

- The body is read to a cap; past that, body checks are skipped and the report
  says so rather than guessing.
- Redirects are followed to a depth of 3, with the SSRF guard re-run on every
  hop.
- Rate limited to 20 requests/hour per IP and 300/hour overall, because the
  service fetches whatever URL it is given.
- The only thing stored is a per-IP request counter for that rate limit, which
  expires within two hours. No analytics, and probe targets are never logged.

Security posture, and the residual risks that were accepted rather than fixed,
are documented in [SECURITY.md](SECURITY.md).

## Reading and running the source

```bash
cd doctor
npm test          # 163 tests, no dependencies of any kind
```

Zero dependencies, runtime or dev — the suite is `node --test`. The rules are
pure functions with no I/O; all network access lives in `src/probe.js`, which is
also where the SSRF guard lives.

The hosted service above is free to use and needs no licence. The **source** is
published for inspection and verification under the same terms as the rest of
this repository: no licence granted at this time, all rights reserved. If you
want to reuse or self-host it, ask.

---

Built by [Twelve Permissions](https://twelvepermissions.com). Free, and
unrelated to anything sold there.
