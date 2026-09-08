/**
 * The sliding window log.
 *
 * The window boundary is the interesting case, and it is the one a check
 * script cannot show you: seeing it requires controlling the clock, because
 * waiting fifteen real minutes is not a test anyone runs twice.
 *
 * So these use tiny windows. That is not a shortcut — the algorithm has no
 * notion of scale, and 40ms exercises exactly the arithmetic that 15 minutes
 * does.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { SlidingWindow, rateLimit } from "../src/ratelimit.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describe("SlidingWindow", () => {
  test("allows up to max, then refuses", () => {
    const w = new SlidingWindow({ name: "t", windowMs: 10_000, max: 3 });

    for (let i = 0; i < 3; i++) {
      assert.equal(w.check("k").allowed, true, `attempt ${i + 1} should be allowed`);
      w.record("k");
    }
    assert.equal(w.check("k").allowed, false, "the 4th must be refused");
  });

  test("keys are independent", () => {
    const w = new SlidingWindow({ name: "t", windowMs: 10_000, max: 1 });
    w.record("a");
    assert.equal(w.check("a").allowed, false);
    // The property the per-email limiter depends on: exhausting one address's
    // budget must not touch anyone else's.
    assert.equal(w.check("b").allowed, true);
  });

  test("the budget refills one slot at a time as hits age out", async () => {
    // THE SLIDING PART. A fixed-window counter resets everything at once at a
    // boundary, which lets a caller send 2*max across it. Here each hit expires
    // on its own schedule, so recovery is gradual.
    const w = new SlidingWindow({ name: "t", windowMs: 40, max: 2 });

    w.record("k");
    await sleep(25);
    w.record("k");
    assert.equal(w.check("k").allowed, false, "at the limit");

    // Wait for the FIRST hit to expire but not the second.
    await sleep(25);
    const state = w.check("k");
    assert.equal(state.allowed, true, "one slot should have freed");
    assert.equal(state.remaining, 1, "exactly one, not the whole budget");
  });

  test("retryAfterMs is truthful, not a guess", () => {
    // Only possible because the timestamps are kept. A fixed-window counter
    // knows the count but not WHEN, so it can only estimate — and an estimate
    // that is too short invites a client to retry into another refusal.
    const w = new SlidingWindow({ name: "t", windowMs: 1000, max: 1 });
    w.record("k");
    const { retryAfterMs } = w.check("k");
    assert.ok(retryAfterMs > 0 && retryAfterMs <= 1000, `implausible: ${retryAfterMs}`);
  });

  test("reset() clears a key", () => {
    // What a successful login does, so a user who mistypes twice and then
    // succeeds is not left carrying a nearly-full failure budget.
    const w = new SlidingWindow({ name: "t", windowMs: 10_000, max: 1 });
    w.record("k");
    assert.equal(w.check("k").allowed, false);
    w.reset("k");
    assert.equal(w.check("k").allowed, true);
  });
});

describe("memory", () => {
  test("sweep() drops keys whose hits have all expired", async () => {
    // The unbounded-Map leak, asserted. A Map keyed by client IP that nothing
    // cleans grows for every scanner and crawler on the internet until the
    // process is killed — a denial of service delivered by the
    // anti-denial-of-service code.
    const w = new SlidingWindow({ name: "t", windowMs: 20, max: 5 });
    for (const ip of ["1.1.1.1", "2.2.2.2", "3.3.3.3"]) w.record(ip);
    assert.equal(w.size, 3);

    await sleep(35);
    w.sweep();
    assert.equal(w.size, 0, "expired keys must be dropped, not merely ignored");
  });

  test("check() does not leave an empty array behind", async () => {
    // The sleep is required, not padding. Expiry is `timestamp <= now - window`,
    // so a hit recorded in the same millisecond as the check has NOT expired —
    // the first version of this test used windowMs: 1 with no wait and failed
    // for that reason. A boundary written as <= needs the clock to actually
    // move before it can be observed.
    const w = new SlidingWindow({ name: "t", windowMs: 5, max: 5 });
    w.record("k");
    assert.equal(w.size, 1);

    await sleep(15);
    w.check("k"); // expires the hit
    assert.equal(w.size, 0, "a key mapping to [] is a leak in miniature");
  });
});

describe("the middleware", () => {
  function call(mw, { method = "GET", ip = "1.2.3.4", path = "/api/x" } = {}) {
    const req = { method, ip, path, originalUrl: path, log: { warn() {} } };
    const out = { headers: {}, status: null, nextCalled: false };
    const res = {
      setHeader: (k, v) => (out.headers[k.toLowerCase()] = v),
      status(c) {
        out.status = c;
        return res;
      },
      json() {
        return res;
      },
    };
    mw(req, res, () => (out.nextCalled = true));
    return out;
  }

  test("RateLimit-Remaining reports the budget AFTER this request", () => {
    // Off by one here ships a limiter whose last success claims one request
    // still available — a small lie that makes a correct client look broken.
    const mw = rateLimit(new SlidingWindow({ name: "t", windowMs: 10_000, max: 3 }));
    assert.equal(call(mw).headers["ratelimit-remaining"], "2");
    assert.equal(call(mw).headers["ratelimit-remaining"], "1");
    assert.equal(call(mw).headers["ratelimit-remaining"], "0");
  });

  test("refuses with 429 and a Retry-After", () => {
    const mw = rateLimit(new SlidingWindow({ name: "t", windowMs: 10_000, max: 1 }));
    call(mw);
    const r = call(mw);

    // 429, not 503. A 503 claims the SERVER is unavailable, invites retries and
    // tells monitoring we are broken. 429 is a statement about the caller.
    assert.equal(r.status, 429);
    assert.equal(r.nextCalled, false);
    assert.ok(Number(r.headers["retry-after"]) >= 1, "Retry-After must be at least 1s");
  });

  test("a refused request is not counted against the budget", () => {
    // Otherwise a client that never backs off extends its own ban forever and
    // Retry-After becomes a lie. Punitive is defensible against a deliberate
    // attacker and cruel to a buggy client belonging to a real user — and we
    // cannot tell them apart from the outside.
    const w = new SlidingWindow({ name: "t", windowMs: 10_000, max: 1 });
    const mw = rateLimit(w);
    call(mw);
    const before = w.check("1.2.3.4").retryAfterMs;
    call(mw);
    call(mw);
    assert.ok(w.check("1.2.3.4").retryAfterMs <= before, "the ban must not extend");
  });

  test("OPTIONS is never counted", () => {
    // A preflight is generated by the browser, not the caller's code, and one
    // real request can produce two — so counting them would silently give a
    // cross-origin client half the stated budget.
    const mw = rateLimit(new SlidingWindow({ name: "t", windowMs: 10_000, max: 1 }));
    call(mw, { method: "OPTIONS" });
    call(mw, { method: "OPTIONS" });
    assert.equal(call(mw).nextCalled, true, "real requests should still have their budget");
  });

  test("keyFn returning null exempts a request", () => {
    // How /health stays exempt. A 429 on a liveness probe tells the platform
    // the process is dead and gets it restarted: never let a defence be able to
    // report the application as broken.
    const mw = rateLimit(new SlidingWindow({ name: "t", windowMs: 10_000, max: 1 }), {
      keyFn: (req) => (req.path.startsWith("/health") ? null : req.ip),
    });
    for (let i = 0; i < 5; i++) {
      assert.equal(call(mw, { path: "/health" }).nextCalled, true);
    }
  });
});
