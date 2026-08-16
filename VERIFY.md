# Verifying a Twelve Permissions seal

Every visual decision in every seal derives from the SHA-256 of its canonical event
record. Nothing is trusted; everything is re-derivable.

## What's on-chain
Each NFT (issuer `rHEiuaYLNQ4UdLqeUrnE9AwEHqsDMr9g9R`, taxon 12, XRP Ledger mainnet):
- **URI** → `https://twelve-permissions.tsharpe.workers.dev/NN.json` (metadata + canonical record)
- **Memo** on the mint transaction, type `twelve-permissions/event-sha256` → the raw event hash

## Re-derive it yourself (requires Node.js)
```
curl -O https://twelve-permissions.tsharpe.workers.dev/events.json
curl -O https://twelve-permissions.tsharpe.workers.dev/generate.js
mkdir pieces && node generate.js
```
The generator prints each piece's sha256. Check three things:
1. The printed hash matches the `Event Hash` attribute in the NFT's metadata.
2. It matches the memo hex (decoded) on the mint transaction at livenet.xrpl.org.
3. The SVG written to `pieces/` is byte-identical to the one the metadata serves.

The ring of 64 ticks around each seal is the hash itself — long tick = 1, short = 0,
starting at the rotation offset derived from the second hash byte. The art *is* the checksum.

Forging a seal for a different event record requires a SHA-256 collision. Good luck.
