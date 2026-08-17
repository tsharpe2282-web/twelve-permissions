/**
 * Fixed-window rate limiter over Workers KV.
 *
 * Reused verbatim (same semantics, same shape) from hosting/src/ratelimit.js,
 * which guards the founder's CDP facilitator credentials from being burned by
 * well-formed forged payments. Here the resource being protected is
 * different — probe() performs an outbound fetch to a caller-supplied URL,
 * which makes this Worker a fetch amplifier: with no limit, anyone can point
 * it at a third party and replay, and both the traffic and the abuse
 * complaint land on the account hosting it — but the counting logic that
 * bounds burn is identical, so it is not reinvented here.
 *
 * FIXED WINDOW, NOT SLIDING: a caller can spend the tail of one window and the
 * head of the next, i.e. up to 2x the limit across a boundary. That is fine
 * here — the goal is bounding request volume, not precision.
 *
 * NO COMPARE-AND-SWAP: KV cannot increment atomically, so simultaneous requests
 * can read the same value and undercount. At this traffic level the window is
 * acceptable, and the failure mode is "slightly too permissive".
 *
 * FAILS OPEN: if KV is unavailable we allow the request. Losing the counter
 * must never stop a legitimate caller from using a free diagnostic tool — an
 * exhausted quota is recoverable, a refused probe is not.
 */
export async function consumeRateLimit(kv, bucket, cfg, nowSec) {
  const windowIndex = Math.floor(nowSec / cfg.windowSec);
  const key = `rl:${bucket}:${windowIndex}`;
  try {
    const count = (Number(await kv.get(key)) || 0) + 1;
    // TTL outlives the window so a straggler request cannot resurrect a stale count.
    await kv.put(key, count, { expirationTtl: Math.max(60, cfg.windowSec * 2) });
    return { ok: count <= cfg.limit, count };
  } catch {
    return { ok: true, count: 0, degraded: true };
  }
}
