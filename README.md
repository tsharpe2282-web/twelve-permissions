# Twelve Permissions — verification apparatus

Twelve NFTs on XRP Ledger mainnet. Twelve permissions a man gave himself while
learning what he could build with AI — the last of which mints only if a robot
dog is delivered to Anchorage, paid for entirely by NFTs his agents minted and
sold. The art is
not illustration: every mark is derived from the SHA-256 of the canonical
authorization record, so the seal *is* the hash, rendered.

This repository exists so you don't have to take any of that on trust. It holds
the generator, the canonical records, and the server source. Re-run them yourself.

Collection: <https://twelvepermissions.com/>
Issuer: `rHEiuaYLNQ4UdLqeUrnE9AwEHqsDMr9g9R` (taxon 12, 5% royalty)

## Verify a seal from first principles

No dependencies. Node only.

```bash
node generate.js            # regenerates every seal from events.json
git status                  # should report no changes
```

The second line is the test. The generator overwrites `pieces/` in place, so if
git reports nothing changed, the published art reproduced byte for byte. If a
single character of a canonical record differed, the palette, the 64-tick ring
and the central sigil would all change with it. Forging a seal means breaking
SHA-256.

To check one piece end to end:

1. Read its canonical record in `events.json`.
2. Take the SHA-256 of that record — it is committed in the NFT's on-chain URI.
3. Re-run the generator and compare the art, byte for byte.
4. Look up the mint transaction in `records/minted.mainnet.json` on any XRPL
   explorer.

`VERIFY.md` has the long version.

## What's here

| Path | What it is |
|---|---|
| `generate.js` | The deterministic seal generator. No dependencies. Byte-identical to the copy served at `/generate.js`. |
| `events.json` | Canonical authorization records — the input to everything |
| `pieces/NN.json` | Per-piece NFT metadata as published |
| `pieces/NN.svg` | The seals, as vectors — regenerated in place by `generate.js` |
| `records/minted.mainnet.json`, `listings.mainnet.json` | Mint and listing transactions, all public on-chain facts |
| `records/refusals.json` | The constraints ledger: standing policy on what the issuing agent will not do. Hash-chained, head anchored on mainnet. Includes an erratum correcting an earlier, overstated version of itself — the anchor of that version is preserved rather than erased. |
| `records/PRECOMMITMENT-12.md` | Binding terms for piece #12, anchored on-chain before the fact |
| `src/worker.js` | The Cloudflare Worker: storefront, MCP server, catalog |
| `src/x402.js` | The x402 seller implementation (Base, USDC) |

## Two artifacts, and only one of them proves anything

Each piece has two images, and the difference matters:

- **`pieces/NN.svg` — the canonical seal.** Derived deterministically from the
  SHA-256 of its record by `generate.js`. This is what verifies, and it is what
  `animation_url` points at in the metadata.
- **`NN.png` — the display image.** The same seal composited over generated
  field artwork by `compose-art.js`. It is what `image` points at, it is what
  you see on a marketplace, and **it is not hash-derived**. The field art is
  decorative.

That split is deliberate and is stated in every piece's metadata under
`verification`. Art that cannot be regenerated from the record proves nothing,
so the provable artifact is kept separate from the pretty one rather than
quietly merged into it.

PNGs are not committed here because they are large and are display-only.
Operational tooling (minting, listing, sale-watching, wallet handling) and
internal planning notes are deliberately not published.

## The MCP server

The collection is installable as a tool. Streamable HTTP, stateless:

```
POST https://twelve-permissions.tsharpe.workers.dev/mcp
```

Tools: `list_pieces`, `get_piece`, `get_buy_transaction`, `get_x402_info`,
`verify_seal`, `get_refusals`.

## The x402 seller, and what it cost to learn

`src/x402.js` is a working x402 seller on Base mainnet, settling real USDC
through the Coinbase CDP facilitator. Seller-side x402 is meaningfully harder
than buyer-side, and several failure modes are undocumented. If you are building
one, these cost us time:

- **`outputSchema: null` is rejected.** The facilitator's schema is not nullable.
  Omit the field entirely rather than sending an explicit null.
- **Verdicts arrive with HTTP 400.** Read the response body regardless of status
  code; a non-2xx does not mean "no answer."
- **A piped secret can upload empty.** A stray blank line produced a binding that
  existed but was falsy. Length-check what you upload.
- **402 challenges must not be cacheable.** A CDN happily caches them, and a
  cached challenge hands a paying agent stale payment requirements — an old
  price, or an item already sold. Send `no-store`.
- **Bazaar discovery declarations belong at the top level** of the 402 body, not
  inside an `accepts` entry. Entries in `accepts` are forwarded verbatim to a
  strict schema that rejects unknown fields.

## Those traps are now a tool: the x402 Doctor

Three of the failures above are checks you can run against your own endpoint,
so they are — along with thirteen more — in [`doctor/`](doctor/).

**https://x402-doctor.tsharpe.workers.dev**

```bash
curl -s -X POST https://x402-doctor.tsharpe.workers.dev/probe \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://your-service.example/paid-endpoint"}'
```

It performs the handshake a paying client would — a `GET` with no `X-PAYMENT`
header — and reports what is wrong with the 402 you answer with, plus a fix for
each finding. Also an MCP server at `POST /mcp`. Free, no payment, no key, and
it never validates through a facilitator, because that would route your traffic
through someone else's facilitator credentials.

Every check states where it came from: `spec` means the specification requires
it, `observed (source)` means we watched a real facilitator reject it and the
source is named. See [`doctor/README.md`](doctor/README.md) for the full table
and [`doctor/SECURITY.md`](doctor/SECURITY.md) for the SSRF posture and the
residual risks that were accepted rather than fixed.

It is unrelated to anything sold here, and nothing about it asks you to buy
anything.

## Licensing

No licence is granted at this time; all rights reserved. The code is published
for inspection and verification. If you want to reuse any of it, ask.

## A note on the origin, and on a correction

A widely-shared post described an AI agent that minted NFTs, sold them, and
funded a robot dog. This collection is an attempt at the same thing from a
standing start, by someone with no platform and no background in software, with
every step recorded so a stranger can check the chain.

The first seven seals were withdrawn and reissued on 16 August 2026. They were
written by an agent that made itself the hero of someone else's story. Nothing
had sold, so no owner was harmed by the correction, and the original mint and
burn transactions remain permanently on the ledger. See ERRATUM-2026-08-16.md.

Nothing here asks to be believed.
