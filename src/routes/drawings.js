import { Router } from "express";
import { query } from "../db.js";

// A Router is a mini-app: middleware and routes grouped together, mounted
// under a prefix by the parent. Paths here are RELATIVE to that prefix, so "/"
// below becomes "/api/drawings" once index.js mounts it. Keeping the prefix out
// of this file means it can be remounted (versioning it as /api/v2/drawings)
// without touching a single route.
export const drawingsRouter = Router();

// GET /api/drawings
//
// No try/catch. Express 5 detects that the handler returned a promise and
// forwards a rejection to the error-handling middleware automatically. In
// Express 4 this was the single most common source of hung requests: an async
// handler that threw would reject silently, the response was never sent, and
// the browser just waited. Worth knowing, because most tutorials online still
// wrap everything in try/catch for a version you are not running.
drawingsRouter.get("/", async (req, res) => {
  const { rows } = await query(
    `select id, title, artist, year, rating, created_at
       from drawings
      order by year desc, id desc`
  );

  // An object, not a bare array. A bare array is a dead end: the day you need
  // to add a total count or a pagination cursor, there is nowhere to put it
  // that isn't a breaking change for every existing client. Stage 3 will thank
  // us for the envelope.
  res.json({ drawings: rows.map(toApiShape) });
});

/**
 * Translate a database row into the API's response shape.
 *
 * Two reasons this function exists rather than sending `rows` straight out:
 *
 * 1. The schema is not the contract. If the response is whatever the table
 *    happens to contain, then adding an internal column — an email, a moderation
 *    flag, a password hash — silently publishes it. This is how real leaks
 *    happen. An explicit mapping means new columns are private by default.
 *
 * 2. Postgres types are not JavaScript types, and `pg` is honest about it
 *    rather than guessing. See the conversion below.
 */
function toApiShape(row) {
  return {
    id: row.id,
    title: row.title,
    artist: row.artist,
    year: row.year,

    // `numeric` arrives as a STRING, not a number.
    //
    // Not a bug — a deliberate refusal to lose data. Postgres numeric is an
    // arbitrary-precision decimal; JavaScript numbers are IEEE-754 doubles and
    // cannot represent every numeric exactly. Converting automatically would
    // silently corrupt values, so `pg` hands back the exact decimal as text and
    // makes YOU decide.
    //
    // A rating in 0.0-5.0 with one decimal place is far inside what a double
    // represents fine, so converting is safe here. For money it would not be —
    // there you keep the string, or store integer cents.
    rating: row.rating === null ? null : Number(row.rating),

    // `timestamptz` arrives as a JS Date (pg does parse this one). JSON has no
    // date type, so serialise explicitly to ISO-8601 UTC rather than relying on
    // whatever JSON.stringify happens to do with a Date.
    createdAt: row.created_at.toISOString(),
  };
}
