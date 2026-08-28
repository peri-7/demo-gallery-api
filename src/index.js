import express from "express";
import { cors } from "./cors.js";

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

app.get("/api/hello", (req, res) => {
  res.json({
    message: "Hello from the API",
    at: new Date().toISOString(),
  });
});

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
