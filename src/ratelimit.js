/**
 * Rate limiting: bounding how much work one caller can make us do.
 *
 * WHY THIS EXISTS, PRECISELY
 * --------------------------
 * password.js hashes with scrypt at N=16384, which costs ~300ms and 16 MiB on
 * Render. That defends a STOLEN TABLE against offline guessing: an attacker
 * with the hashes can only try a few per second per core instead of billions.
 *
 * It does nothing whatsoever about someone hammering POST /api/auth/login.
 * Worse, it inverted the economics — every guess now costs the ATTACKER one
 * HTTP request and costs US 300ms of CPU and 16 MiB of a 512 MiB instance. We
 * made offline attacks expensive by making online attacks cheap for them and
 * expensive for us. Rate limiting is the other half of that trade, and without
 * it the slow hash is a liability at the front door.
 *
 * So this file answers two threats at once:
 *   1. ONLINE PASSWORD GUESSING — bounded attempts per address, per hour
 *   2. RESOURCE EXHAUSTION      — bounded work per caller, full stop
 *
 * THE ALGORITHM: SLIDING WINDOW LOG
 * ---------------------------------
 * We keep the timestamps of a key's recent hits, discard those older than the
 * window, and count what remains. Exact, and it makes Retry-After truthful:
 * we know precisely when the oldest hit falls out.
 *
 * The cheaper classic is a FIXED WINDOW COUNTER — one integer per key, reset
 * every windowMs. It has a real flaw: a caller can send `max` at 11:59:59 and
 * another `max` at 12:00:01, which is 2*max in two seconds while never
 * exceeding the limit as written. Our window is small (max is 10, not 10,000),
 * so the log's O(max) memory per key is free and the exactness is worth having.
 *
 * WHERE THE STATE LIVES, AND WHY THAT IS A KNOWN COMPROMISE
 * ---------------------------------------------------------
 * In a Map, in this process. Which means:
 *
 *   - It resets on every deploy, and on every wake from Render's sleep. An
 *     attacker who notices could reset their own budget by idling 15 minutes,
 *     though at that point they are already rate-limited to something harmless.
 *   - It is PER INSTANCE. With two instances behind a load balancer, a limit of
 *     10 becomes an effective limit of 20 and neither process knows. This is
 *     the single reason production systems reach for Redis, and it is not a
 *     detail — it is the whole reason the shared-store version exists.
 *
 * Render's free tier runs exactly one instance, so the second problem is not a
 * problem HERE. It becomes one the instant that changes, which is why it is
 * written down rather than quietly relied upon.
 *
 * The alternative we deliberately did NOT take is Postgres. A counter row per
 * request turns every read into a write, which is the same mistake 4a avoided
 * by refreshing last_seen_at at 5-minute granularity instead of per request.
 * Rate limiting must be cheaper than the thing it protects, or it is just a
 * second way to fall over.
 */

import { logger } from "./logger.js";

/**
 * All live windows, so ONE timer can sweep them all.
 *
 * This registry is not tidiness. A Map keyed by client IP that nothing ever
 * cleans is an UNBOUNDED MEMORY LEAK: every scanner, crawler and bored botnet
 * on the internet permanently costs us an entry. The process would grow until
 * Render killed it — a denial of service delivered by the anti-denial-of-service
 * code. The sweeper is part of the mechanism, not housekeeping.
 */
const windows = new Set();

export class SlidingWindow {
  /**
   * @param {object} opts
   * @param {string} opts.name      identifies this limiter in logs and headers
   * @param {number} opts.windowMs  how far back we look
   * @param {number} opts.max       hits allowed within that span
   */
  constructor({ name, windowMs, max }) {
    this.name = name;
    this.windowMs = windowMs;
    this.max = max;
    /** @type {Map<string, number[]>} key -> ascending hit timestamps */
    this.hits = new Map();
    windows.add(this);
  }

  /**
   * Read-only: may this key proceed, and what should we tell it?
   *
   * Separated from record() on purpose. For per-IP limiting the two happen
   * together, but the failed-login counter needs to CHECK before doing the work
   * and RECORD only once the outcome is known. Fusing them into one call would
   * make that impossible to express — the same reason sessions.js has no idea
   * HTTP exists.
   */
  check(key) {
    const now = Date.now();
    const cutoff = now - this.windowMs;

    // Timestamps are appended in order, so everything expired is a prefix. We
    // could findIndex + slice; a while loop over an array that is at most `max`
    // long is simpler and allocates nothing.
    const timestamps = this.hits.get(key);
    if (timestamps === undefined) {
      return { allowed: true, remaining: this.max, retryAfterMs: 0, resetMs: this.windowMs };
    }
    while (timestamps.length > 0 && timestamps[0] <= cutoff) timestamps.shift();

    // An emptied array is a live leak in miniature: delete rather than keep a
    // key mapping to [].
    if (timestamps.length === 0) {
      this.hits.delete(key);
      return { allowed: true, remaining: this.max, retryAfterMs: 0, resetMs: this.windowMs };
    }

    const oldestExpiresIn = timestamps[0] + this.windowMs - now;
    const allowed = timestamps.length < this.max;

    return {
      allowed,
      remaining: Math.max(0, this.max - timestamps.length),
      // How long until ONE slot frees up — which is what a caller at the limit
      // actually wants to know. Truthful because we kept the timestamps.
      retryAfterMs: allowed ? 0 : oldestExpiresIn,
      resetMs: oldestExpiresIn,
    };
  }

  /** Count a hit against this key. */
  record(key) {
    const timestamps = this.hits.get(key);
    if (timestamps === undefined) this.hits.set(key, [Date.now()]);
    else timestamps.push(Date.now());
  }

  /** Forget a key entirely — used to clear failures after a correct password. */
  reset(key) {
    this.hits.delete(key);
  }

  /** Drop every key whose most recent hit has aged out. Called by the sweeper. */
  sweep(now = Date.now()) {
    const cutoff = now - this.windowMs;
    for (const [key, timestamps] of this.hits) {
      // The LAST timestamp is the newest; if even that has expired, so has
      // everything before it and the whole key can go.
      if (timestamps.length === 0 || timestamps[timestamps.length - 1] <= cutoff) {
        this.hits.delete(key);
      }
    }
  }

  /** Total tracked keys — for the check script, so the leak is observable. */
  get size() {
    return this.hits.size;
  }
}

/**
 * One sweeper for every window.
 *
 * .unref() is the important call. Without it this timer keeps the Node event
 * loop alive forever, so the process never exits on its own: `npm test` hangs,
 * Ctrl-C feels broken, and a graceful shutdown never completes. An unref'd
 * timer still fires while other work is pending, and simply stops counting as a
 * reason to stay running. Any long-lived interval in a server needs this.
 */
const SWEEP_INTERVAL_MS = 60_000;
const sweeper = setInterval(() => {
  const now = Date.now();
  for (const window of windows) window.sweep(now);
}, SWEEP_INTERVAL_MS);
sweeper.unref();

/**
 * Express middleware around a window.
 *
 * @param {SlidingWindow} window
 * @param {object} [opts]
 * @param {(req) => string|null} [opts.keyFn]  null means "do not limit this request"
 */
export function rateLimit(window, { keyFn = (req) => req.ip } = {}) {
  return function rateLimitMiddleware(req, res, next) {
    // OPTIONS is never counted. A preflight is generated by the browser, not
    // by the caller's code, and one real request can produce two. Counting them
    // would mean a cross-origin client silently gets half the stated budget —
    // and worse, a 429 on a preflight surfaces in the browser as an opaque CORS
    // failure, which is the least debuggable error message we could produce.
    if (req.method === "OPTIONS") return next();

    const key = keyFn(req);
    if (key === null) return next();

    const state = window.check(key);

    // draft-ietf-httpapi-ratelimit-headers. Sent on EVERY response, not just
    // rejections, so a well-behaved client can slow down before being refused
    // rather than discovering the limit by hitting it.
    //
    // Note the -1. check() reports the budget BEFORE this request; the header
    // must report it AFTER, because that is what the client has left when it
    // reads the response. Getting this backwards ships a limiter whose last
    // response before a 429 claims one request still available — a small lie
    // that makes a correct client look broken.
    res.setHeader("RateLimit-Limit", String(window.max));
    res.setHeader(
      "RateLimit-Remaining",
      String(state.allowed ? state.remaining - 1 : 0)
    );
    res.setHeader("RateLimit-Reset", String(Math.ceil(state.resetMs / 1000)));

    if (!state.allowed) {
      const retryAfter = Math.max(1, Math.ceil(state.retryAfterMs / 1000));
      res.setHeader("Retry-After", String(retryAfter));

      (req.log ?? logger).warn("rate limit refused", {
        limiter: window.name,
        method: req.method,
        path: req.originalUrl,
        key,
        retryAfterSeconds: retryAfter,
        // How many keys this window is currently tracking. Cheap, and it is
        // the number that would reveal the unbounded-Map leak if the sweeper
        // ever stopped running.
        trackedKeys: window.size,
      });

      // 429 Too Many Requests. Not 503: 503 means the SERVER is unavailable,
      // which invites retries and tells monitoring we are broken. 429 says the
      // server is fine and this particular caller must wait — a statement about
      // them, not about us.
      return res.status(429).json({
        error: "Too many requests",
        retryAfterSeconds: retryAfter,
      });
    }

    // Recorded only when allowed. A refused request did almost no work, so
    // counting it would be charging for something we did not do — and it would
    // mean a client that never backs off extends its own ban forever, making
    // Retry-After a lie. The punitive alternative is defensible against a
    // deliberate attacker; it is cruel to a buggy client belonging to a real
    // user, and we cannot tell them apart.
    window.record(key);
    next();
  };
}

/** Exported for the check script and for tests. */
export function _allWindows() {
  return windows;
}
