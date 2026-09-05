/**
 * Sessions: turning a string back into a user, on every single request.
 *
 * The mental model to hold while reading this file:
 *
 *     THE TOKEN IS A NAME FOR A ROW. IT CARRIES NO AUTHORITY OF ITS OWN.
 *
 * Nothing here "remembers" that someone is logged in. There is no in-memory
 * map of live users, no state accumulating in the process. Every request starts
 * from nothing, hashes the string it was given, looks the row up, and forgets
 * again. That is what makes the server restartable, deployable, and — in Stage
 * 5 — runnable as more than one instance: the session lives in Postgres, so any
 * process can answer any request.
 *
 * It is also what makes logout real. Delete the row and the string instantly
 * names nothing, everywhere, at once.
 *
 * Stage 4a stops at the door: this file mints, finds and destroys sessions.
 * How the token reaches the browser and comes back across two hostnames is
 * Stage 4b, and deliberately not decided here — notice that nothing below
 * mentions cookies, headers, or HTTP at all.
 */

import { randomBytes, createHash } from "node:crypto";
import { query } from "./db.js";

/**
 * How long a session lasts.
 *
 * A policy number, not an environment one — it means the same thing on a laptop
 * and in production, so it does not belong in .env. (Ports and origins DO
 * differ per environment; this does not. That is the actual test for whether
 * something is configuration.)
 *
 * Seven days is a compromise, and both directions have a real cost: shorter
 * means users re-enter passwords more often, which trains them to type
 * passwords into anything that asks; longer means a stolen token stays useful
 * for longer. There is no correct answer, only a chosen one.
 */
const SESSION_TTL_DAYS = 7;

/**
 * How stale last_seen_at is allowed to get before we bother writing it.
 * The reasoning is in findSession() — it is more interesting than it looks.
 */
const LAST_SEEN_REFRESH_MINUTES = 5;

/** 32 bytes = 256 bits of entropy. */
const TOKEN_BYTES = 32;

/**
 * A hard cap on the length of anything we will treat as a token.
 *
 * Our tokens are 43 characters. Anything wildly longer is not a token that got
 * corrupted, it is someone poking at the endpoint — and sha256 over a 50 MB
 * request body is free work we do not need to donate. Same principle as the
 * password length cap: bound the untrusted input before spending on it.
 */
const MAX_TOKEN_LENGTH = 256;

/**
 * Hash a token for storage and lookup.
 *
 * sha256, and deliberately NOT the slow scrypt used for passwords. Slow hashing
 * exists to defeat guessing, and guessing only threatens something guessable.
 * This value came from the OS's CSPRNG: there is no wordlist of 256-bit random
 * numbers, and no hardware brute-forces one. Making this slow would buy nothing
 * and would burn 35ms of CPU on every authenticated request.
 *
 *     Slow hashing protects LOW-ENTROPY secrets.
 *     High-entropy secrets need only a one-way function.
 *
 * No salt here either, for the same reason: a salt defeats precomputation, and
 * you cannot usefully precompute against 2^256 possibilities.
 */
function hashToken(token) {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Mint a new session for a user.
 *
 * Returns the raw token. This is THE ONLY MOMENT that value exists in a form
 * anyone can use — it is never written down, never logged, and cannot be
 * recovered afterwards, because the database holds only its sha256. If the
 * caller loses it, the session is unreachable and the only remedy is a new
 * login. That is the intended property, not a limitation.
 */
export async function createSession(userId) {
  // base64url, not hex: same 256 bits in 43 characters instead of 64, and the
  // alphabet is URL- and header-safe with no escaping. randomBytes draws from
  // the operating system's CSPRNG — never Math.random(), whose internal state
  // is predictable from its own output.
  const token = randomBytes(TOKEN_BYTES).toString("base64url");

  // The deadline is computed by POSTGRES, not by Node.
  //
  // Two reasons. The expiry check at read time also uses now(), so both sides
  // of the comparison come from one clock and cannot disagree — a server whose
  // clock has drifted cannot mint sessions that are already expired, or that
  // outlive their TTL. And it removes any chance of a timezone mistake in
  // JavaScript's date handling reaching the column.
  const result = await query(
    `insert into sessions (user_id, token_hash, expires_at)
     values ($1, $2, now() + ($3 || ' days')::interval)
     returning id, created_at, expires_at`,
    [userId, hashToken(token), String(SESSION_TTL_DAYS)]
  );

  const row = result.rows[0];
  return {
    token,
    id: row.id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  };
}

/**
 * Resolve a token to its session and user, or null.
 *
 * Null covers every failure identically: no such session, expired, deleted,
 * garbage input. The caller cannot tell which, and neither can the client —
 * "your token is expired" and "that token never existed" are the same 401. An
 * endpoint that distinguishes them is an oracle for probing which tokens once
 * existed.
 */
export async function findSession(token) {
  if (typeof token !== "string") return null;
  if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) return null;

  // One indexed lookup on token_hash (the UNIQUE constraint is the index), plus
  // a join for the user. Note that expiry is enforced HERE, in the WHERE clause
  // — not by a cleanup job, and not in JavaScript after fetching the row.
  //
  // That ordering is the security-relevant part: an expired row is harmless the
  // instant it expires, whether or not anything has got round to deleting it.
  // If expiry were enforced by a sweeper, a sweeper that failed silently would
  // be a vulnerability. Enforced at read time, a failed sweeper is only untidy.
  const result = await query(
    `select
       s.id            as session_id,
       s.created_at    as session_created_at,
       s.expires_at    as session_expires_at,
       s.last_seen_at  as session_last_seen_at,
       u.id            as user_id,
       u.email         as user_email
     from sessions s
     join users u on u.id = s.user_id
     where s.token_hash = $1
       and s.expires_at > now()`,
    [hashToken(token)]
  );

  if (result.rowCount === 0) return null;
  const row = result.rows[0];

  // Refresh last_seen_at — but not on every request.
  //
  // The naive version makes the lookup an UPDATE ... RETURNING, which is one
  // round trip and reads beautifully. It also turns EVERY authenticated read
  // into a write. Postgres writes a whole new row version per update (it never
  // edits in place), so that is a new tuple, WAL traffic, index churn and work
  // for autovacuum — on requests that logically changed nothing. On a busy
  // endpoint this is a well-known way to make a read-heavy app write-bound.
  //
  // The fix is not to drop the feature but to make the write RARE: nobody needs
  // "last seen" accurate to the second. At five-minute granularity the write
  // happens roughly once per five minutes per active session instead of once
  // per request, and the feature is just as useful.
  //
  // Awaited rather than fired-and-forgotten: an un-awaited promise that rejects
  // is an unhandled rejection, and in Node that is a process-level crash.
  const lastSeen = row.session_last_seen_at;
  const staleBefore = Date.now() - LAST_SEEN_REFRESH_MINUTES * 60_000;
  if (lastSeen === null || lastSeen.getTime() < staleBefore) {
    await query("update sessions set last_seen_at = now() where id = $1", [row.session_id]);
  }

  return {
    session: {
      id: row.session_id,
      createdAt: row.session_created_at,
      expiresAt: row.session_expires_at,
    },
    user: {
      id: row.user_id,
      email: row.user_email,
    },
  };
}

/**
 * Log out: delete the row the token names.
 *
 * Returns true if a session was actually deleted. The caller should NOT expose
 * that difference — logging out twice, or logging out with a token that was
 * never valid, should both look like success. There is nothing for a client to
 * do differently, and the distinction only tells a prober whether a token
 * existed.
 *
 * Note there is no "invalidate the token" step. The token was never anything
 * but a name; once the row is gone it refers to nothing, immediately, for every
 * process, with no cache to expire. Revocation is free precisely because the
 * authority lived in the row rather than in the string.
 */
export async function destroySession(token) {
  if (typeof token !== "string") return false;
  if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) return false;

  const result = await query("delete from sessions where token_hash = $1", [hashToken(token)]);
  return result.rowCount > 0;
}

/**
 * Log out everywhere — the button every account settings page should have.
 *
 * This is the one that is impossible to do honestly with a stateless signed
 * token: there is no row to delete, so "revoking" one means keeping a list of
 * revoked tokens, which is the database lookup the stateless design existed to
 * avoid. Kept here because it is the clearest single argument for this design,
 * and Stage 4b will weigh it against the costs.
 *
 * Served by sessions_user_id_idx (migration 006).
 */
export async function destroyAllSessionsForUser(userId) {
  const result = await query("delete from sessions where user_id = $1", [userId]);
  return result.rowCount;
}
