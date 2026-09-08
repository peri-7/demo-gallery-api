// The database layer. Everything that touches Postgres goes through here.
//
// This module is imported once and its top-level code runs once, for the life
// of the process. That is the whole reason the pool works: a long-running
// Express server opens a handful of connections at boot and reuses them for
// every request until the process dies. See THEORY.md §10.

import pg from "pg";
import { logger } from "./logger.js";

// `pg` is a CommonJS package. Node can usually synthesise named exports from
// one, but it does it by static analysis and it is not guaranteed. Importing
// the default object and destructuring is the form that always works.
const { Pool } = pg;

// Fail at boot, not at the first request.
//
// A server that starts happily and then 500s on every query is much harder to
// diagnose than one that refuses to start with a clear reason. Crash early,
// crash loudly: Render will show this in the deploy log instead of marking the
// service live and serving errors.
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL is not set. Copy .env.example to .env and fill it in."
  );
}

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,

  // Maximum real connections this process will ever hold open.
  //
  // The number that matters is (instances x max) <= the database's connection
  // limit. One Render free instance x 5 is trivially safe. Bigger is not
  // better: connections are a scarce server-side resource, not a client-side
  // throughput dial. Five is plenty for a server this size — a query takes
  // ~5ms, so five connections is ~1000 queries/second of headroom.
  max: 5,

  // Close a connection that has sat unused this long. Keeps us from pinning
  // connections we are not using, and lets Neon scale its compute to zero.
  idleTimeoutMillis: 30_000,

  // How long a caller waits for a free connection before giving up. Without
  // this, a pool that is exhausted or a database that is unreachable makes
  // requests hang forever instead of failing. Generous here because Neon's
  // compute may need a second or two to wake from idle.
  connectionTimeoutMillis: 10_000,
});

// Connections can die while sitting idle in the pool — the database restarts,
// a load balancer times them out, the network blips. That surfaces as an error
// event on the pool with no query to attach it to. Without this listener Node
// treats it as an unhandled 'error' event and kills the process.
//
// The pool discards the broken connection and opens a fresh one on next use,
// so logging is genuinely the right response.
pool.on("error", (err) => {
  // The base logger, with no reqId — correctly so, and worth noticing. This
  // fires on a connection sitting IDLE, so there is no request to attribute it
  // to. A line with no reqId is a real signal here: it means "this happened to
  // the server, not to somebody".
  //
  // Passing the whole error rather than err.message: the logger redacts
  // connection strings by value, so a Postgres error that quotes the DSN
  // cannot leak the password through a field nobody thought to check.
  logger.error("idle database client errored", { err });
});

/**
 * Run a single query on a borrowed connection, then return it to the pool.
 *
 * Always pass values as the second argument, never interpolated into the SQL
 * string. The text and the values travel over the wire as separate things, so
 * a value can never be parsed as syntax. THEORY.md §10.
 */
export function query(text, params) {
  return pool.query(text, params);
}
