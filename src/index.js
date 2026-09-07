import express from "express";
import { cors } from "./cors.js";
import { csrf } from "./csrf.js";
import { pool } from "./db.js";
import { drawingsRouter } from "./routes/drawings.js";
import { authRouter } from "./routes/auth.js";

const app = express();

// Request log. Runs on every request because it has no path argument.
// res.on("finish") fires once the response has been handed to the socket, so
// we can log the status we actually sent.
app.use((req, res, next) => {
  const started = Date.now();
  res.on("finish", () => {
    console.log(
      `${req.method} ${req.originalUrl} ${res.statusCode} ${Date.now() - started}ms` +
        ` origin=${req.headers.origin ?? "-"}`
    );
  });
  next();
});

// Before the routes: a preflight must be answered here, not fall through to a
// handler that has no idea what OPTIONS means.
app.use(cors);

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
