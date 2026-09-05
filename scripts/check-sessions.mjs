/**
 * A runnable check of src/sessions.js, against the real dev database.
 *
 *   npm run check:sessions
 *
 * It creates one throwaway user, exercises the whole lifecycle, and deletes it
 * again. Nothing asserts — it prints what happened. The interesting lines are
 * the ones showing that an expired row and a deleted row are indistinguishable
 * from the outside, and that the stored hash is not the token.
 */

import { query, pool } from "../src/db.js";
import { hashPassword } from "../src/password.js";
import {
  createSession,
  findSession,
  destroySession,
  destroyAllSessionsForUser,
} from "../src/sessions.js";

const url = new URL(process.env.DATABASE_URL);
console.log(`target host : ${url.host}\n`);

const email = `check-sessions-${Date.now()}@example.invalid`;
const { rows } = await query(
  "insert into users (email, password_hash) values ($1, $2) returning id",
  [email, await hashPassword("a throwaway password")]
);
const userId = rows[0].id;
console.log(`created user ${userId}\n`);

try {
  // --- minting -------------------------------------------------------------
  const a = await createSession(userId);
  console.log("createSession:");
  console.log(`  token       ${a.token}`);
  console.log(`  length      ${a.token.length} chars for 256 bits of entropy`);
  console.log(`  expires_at  ${a.expiresAt.toISOString()}`);

  const stored = await query("select token_hash from sessions where id = $1", [a.id]);
  console.log(`  stored as   ${stored.rows[0].token_hash}`);
  console.log(`  same value? ${stored.rows[0].token_hash === a.token}   <- must be false\n`);

  // --- lookup --------------------------------------------------------------
  const found = await findSession(a.token);
  console.log("findSession with the real token:");
  console.log(`  user  ${found.user.email}`);
  console.log(`  seen  ${(await lastSeen(a.id))?.toISOString() ?? "null"}   <- set on first use\n`);

  console.log("findSession with input that is not a valid token:");
  for (const bad of ["", "not-a-real-token", a.token.slice(0, -1) + "X", "x".repeat(5000), null]) {
    const label = bad === null ? "null" : `${JSON.stringify(bad.slice(0, 24))}${bad.length > 24 ? `… (${bad.length})` : ""}`;
    console.log(`  ${label.padEnd(34)} -> ${await findSession(bad)}`);
  }

  // --- expiry --------------------------------------------------------------
  // Backdate the row rather than waiting seven days. This is exactly what an
  // expired session is: an ordinary row whose expires_at has passed. Nothing
  // deleted it, nothing swept it — it simply stops matching the WHERE clause.
  await query("update sessions set expires_at = now() - interval '1 second' where id = $1", [a.id]);
  console.log(`\nafter backdating expires_at:`);
  console.log(`  row still in table? ${(await query("select 1 from sessions where id = $1", [a.id])).rowCount === 1}`);
  console.log(`  findSession        -> ${await findSession(a.token)}   <- harmless without being deleted\n`);

  // --- logout --------------------------------------------------------------
  const b = await createSession(userId);
  console.log("destroySession:");
  console.log(`  before  ${(await findSession(b.token)) !== null}`);
  console.log(`  delete  ${await destroySession(b.token)}`);
  console.log(`  after   ${(await findSession(b.token)) !== null}`);
  console.log(`  again   ${await destroySession(b.token)}   <- false, and the route must not reveal it\n`);

  // --- logout everywhere ---------------------------------------------------
  await Promise.all([createSession(userId), createSession(userId), createSession(userId)]);
  const live = await query("select count(*)::int as n from sessions where user_id = $1", [userId]);
  console.log("destroyAllSessionsForUser:");
  console.log(`  sessions before  ${live.rows[0].n}`);
  console.log(`  deleted          ${await destroyAllSessionsForUser(userId)}`);
  const after = await query("select count(*)::int as n from sessions where user_id = $1", [userId]);
  console.log(`  sessions after   ${after.rows[0].n}\n`);

  // --- the cascade ---------------------------------------------------------
  await createSession(userId);
  await query("delete from users where id = $1", [userId]);
  const orphans = await query("select count(*)::int as n from sessions where user_id = $1", [userId]);
  console.log("deleting the user:");
  console.log(`  sessions left behind  ${orphans.rows[0].n}   <- on delete cascade, enforced by Postgres`);
} finally {
  // Idempotent: the cascade block above may already have removed it.
  await query("delete from users where id = $1", [userId]);
  await pool.end();
}

async function lastSeen(sessionId) {
  const r = await query("select last_seen_at from sessions where id = $1", [sessionId]);
  return r.rows[0]?.last_seen_at ?? null;
}
