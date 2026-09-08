import express from "express";
import { cors } from "./cors.js";
import { csrf } from "./csrf.js";
import { SlidingWindow, rateLimit } from "./ratelimit.js";
import { pool } from "./db.js";
import { drawingsRouter } from "./routes/drawings.js";
import { authRouter } from "./routes/auth.js";

const app = express();

/**
 * HOW MANY PROXIES SIT IN FRONT OF US.
 *
 * req.ip is the peer address of the socket. In production that is RENDER'S
 * PROXY, not the caller — so a per-IP rate limiter would put the entire
 * internet into one bucket and refuse everybody at once.
 *
 * The real client address is in X-Forwarded-For, which is a comma-separated
 * chain that each proxy APPENDS to. Everything to the right was written by
 * infrastructure we trust; everything to the left was written by someone we do
 * not. So the setting is a COUNT: skip this many entries from the right, and
 * take the next one.
 *
 * The popular wrong answer is `app.set("trust proxy", true)`, which trusts the
 * whole chain and therefore takes the LEFTMOST entry — the one the client
 * wrote. Any attacker can then send `X-Forwarded-For: 1.2.3.4`, get a fresh
 * rate-limit bucket on every request, and walk straight through. A limiter
 * configured that way is worse than no limiter, because it looks like it works.
 *
 * Hence a number, from the environment: 0 locally where nothing is in front of
 * us, and whatever production actually has. Do not guess it — the request log
 * below prints xff, so you can count the entries on a real request first.
 */
const trustProxyHops = Number.parseInt(process.env.TRUST_PROXY_HOPS ?? "0", 10);
if (Number.isNaN(trustProxyHops) || trustProxyHops < 0) {
  throw new Error(`TRUST_PROXY_HOPS must be a non-negative integer, got: ${process.env.TRUST_PROXY_HOPS}`);
}
// 0 is falsy to Express and means "trust nothing", which is the correct local
// default: req.ip is then the socket peer and X-Forwarded-For is ignored.
app.set("trust proxy", trustProxyHops);

// Request log. Runs on every request because it has no path argument.
// res.on("finish") fires once the response has been handed to the socket, so
// we can log the status we actually sent.
//
// ip and xff are both here deliberately, and they are how you configure the
// setting above: send one real request to production and compare them. If
// xff has two entries and ip is the rightmost, TRUST_PROXY_HOPS is wrong.
app.use((req, res, next) => {
  const started = Date.now();
  res.on("finish", () => {
    console.log(
      `${req.method} ${req.originalUrl} ${res.statusCode} ${Date.now() - started}ms` +
        ` origin=${req.headers.origin ?? "-"}` +
        ` ip=${req.ip ?? "-"}` +
        ` xff=${req.headers["x-forwarded-for"] ?? "-"}`
    );
  });
  next();
});

// Before the routes: a preflight must be answered here, not fall through to a
// handler that has no idea what OPTIONS means.
app.use(cors);

/**
 * The global floor: a generous per-IP cap on everything.
 *
 * This is not the login defence — that lives in routes/auth.js and is far
 * tighter. This one exists so that no single caller can occupy the process,
 * whatever they are asking for. A crawler looping GET /api/drawings is not
 * malicious and still exhausts a 5-connection pool.
 *
 * Placed immediately after cors and BEFORE csrf and express.json(), because a
 * limiter that runs late has already paid for the thing it was meant to
 * prevent. Body parsing in particular is real work done on a stranger's behalf.
 *
 * But it must come AFTER cors, and that ordering is not cosmetic: a 429 with no
 * Access-Control-Allow-Origin header reaches the browser as an opaque CORS
 * failure, so our own client would report "network error" instead of "you are
 * being rate limited". A defence nobody can diagnose gets removed.
 */
const globalLimit = new SlidingWindow({
  name: "global-ip",
  windowMs: 60_000,
  max: Number.parseInt(process.env.RATE_LIMIT_GLOBAL_PER_MINUTE ?? "120", 10),
});
app.use(
  rateLimit(globalLimit, {
    // null means "do not limit this request". The liveness probe is exempt for
    // the same reason /health touches no database: it must answer whether the
    // PROCESS is alive, and a 429 would tell Render we are dead and get us
    // restarted. Never let a defence be able to report the app as broken.
    keyFn: (req) => (req.path.startsWith("/health") ? null : req.ip),
  })
);

// CSRF, immediately after CORS and before anything that can change state.
//
// Order matters twice here. It must come AFTER cors, so a preflight is already
// answered and never reaches it. And it must come before the routes, because a
// rule that only some handlers remember to apply is a rule that the next
// endpoint will forget — the same argument that made requireAuth middleware.
//
// It needs no request body, so it does not matter that express.json() has not
// run yet: the decision is made entirely from the Origin header.
app.use(csrf);

// Parses JSON request bodies into req.body. Without it, req.body is undefined
// and no error is thrown — see QUIZ.md E3.
app.use(express.json());

// Liveness probe. Deliberately touches nothing: no database, no disk, no
// network. It answers "is this process running and able to respond?" and
// nothing else. If it checked the DB, a DB blip would make the platform think
// the server is dead and restart it — which does not fix a DB blip.
app.get("/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

// Readiness probe — the counterpart to /health above, and the reason that one
// stays empty. This asks "can I actually serve traffic?", which means touching
// the database. Monitoring may alert on this; the platform must NOT restart on
// it, because restarting a healthy process does not fix an unreachable
// database. Liveness and readiness are different questions with different
// consequences, and conflating them causes restart loops.
app.get("/health/db", async (req, res) => {
  const started = Date.now();
  try {
    await pool.query("select 1");
    res.json({
      status: "ok",
      latencyMs: Date.now() - started,
      pool: { total: pool.totalCount, idle: pool.idleCount, waiting: pool.waitingCount },
    });
  } catch (err) {
    console.error("Readiness check failed:", err.message);
    res.status(503).json({ status: "unavailable" });
  }
});

app.get("/api/hello", (req, res) => {
  res.json({
    message: "Hello from the API",
    at: new Date().toISOString(),
  });
});

// Mount the router under its prefix. Every path inside drawings.js is relative
// to this string, and this is the only place it appears.
app.use("/api/drawings", drawingsRouter);

// Authentication. Mounted AFTER express.json() above, because every endpoint in
// it reads req.body — middleware order is execution order, and a router mounted
// before the body parser receives req.body === undefined with no error at all
// (QUIZ.md E3).
app.use("/api/auth", authRouter);

// 404: reached only if no route above matched.
app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

// Error handler: four arguments is how Express tells it apart from ordinary
// middleware. Never leak err.message to the client — see QUIZ.md E14.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});
