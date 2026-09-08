/**
 * See what the logger does. A demonstration, not a test — nothing asserts.
 *
 *   npm run check:logging                  (pretty, the local default)
 *   LOG_FORMAT=json npm run check:logging  (what production emits)
 *   LOG_LEVEL=debug npm run check:logging  (turn the quiet lines on)
 *
 * The interesting section is the last one. Every call there is a mistake a
 * real person makes while debugging, and the point is that NONE of them leak,
 * because the logger refuses at the key rather than trusting the caller to
 * remember.
 */

import { logger, logConfig } from "../src/logger.js";

console.log(`\nlevel=${logConfig.level} format=${logConfig.format}\n`);

// ---------------------------------------------------------------------------
console.log("1. Levels. debug is below the default threshold, so it vanishes.");
console.log("   Re-run with LOG_LEVEL=debug to make it appear.\n");

logger.debug("health probe", { path: "/health" });
logger.info("api listening", { port: 3000 });
logger.warn("rate limit refused", { limiter: "auth-ip", retryAfterSeconds: 900 });
logger.error("readiness check failed", { err: new Error("connection terminated") });

// ---------------------------------------------------------------------------
console.log("\n2. Correlation. Two requests interleaving — tell them apart by reqId.\n");

const a = logger.child({ reqId: "a3f9c1d2" });
const b = logger.child({ reqId: "b7e20455" });

a.info("login attempt");
b.info("upload url requested");
a.warn("rate limit refused", { limiter: "login-failures-per-email" });
b.info("request", { status: 200, ms: 41 });
a.info("request", { status: 429, ms: 2 });

console.log(`
Without reqId those five lines are one shuffled heap. THAT is the argument for
structured logging — not the JSON. Node serves requests concurrently, so log
order is not request order, and a line's neighbours tell you nothing.
`);

// ---------------------------------------------------------------------------
console.log("3. Redaction. Every call below is a real debugging habit.\n");

// The classic. Since Stage 4b a session credential is in a header on EVERY
// request, so this one line would write live session tokens to disk.
logger.info("incoming headers", {
  headers: {
    "content-type": "application/json",
    cookie: "session=VA6_wbo9ZGt-REAL-SESSION-TOKEN-HERE",
    authorization: "Bearer VA6_wbo9ZGt-REAL-SESSION-TOKEN-HERE",
    origin: "https://demo-gallery-nine.vercel.app",
  },
});

// "Just log the body so I can see what they sent."
logger.info("signup body", { body: { email: "someone@example.com", password: "hunter2" } });

// Nested past the obvious place — the check is applied at every depth, not
// just the top level.
logger.info("session created", {
  session: { user: { id: "4710908f", email: "someone@example.com" }, token: "SECRET" },
});

// A value that is a secret regardless of the key it arrived under. Postgres
// errors quote the DSN, and nobody writes `logger.info("...", { database_url })`
// on purpose — it arrives inside an error message written by a library.
logger.error("startup failed", {
  err: new Error("could not connect to postgresql://user:hunter2@ep-x.neon.tech/neondb"),
});

// Not a secret, and NOT redacted — worth showing, because a redactor that
// eats everything is one people switch off.
logger.info("request", { method: "POST", path: "/api/auth/login", status: 401, ms: 312 });

console.log(`
Notes
-----
- Redaction is keyed on the FIELD NAME, at every depth, so it cannot be
  forgotten at a call site. That is the whole design: a rule you have to
  remember is a rule that fails on the day you are tired.
- It is a blocklist, so it is not complete. A token stored as { blah: "..." }
  still gets through. It catches every conventional name, which is what
  actually happens in practice — but do not mistake it for a guarantee.
- The Error objects print their message, name, code and stack. Note why that
  needs code: JSON.stringify(new Error("boom")) is "{}", because those fields
  are non-enumerable. Logging an error naively into a structured logger is the
  classic way to emit a line that says nothing at all.
- HttpOnly stops page JavaScript from reading the session cookie. It does
  nothing about this process printing it. Different threat, different fix —
  the same precision QUIZ J3 was asking for.
`);
