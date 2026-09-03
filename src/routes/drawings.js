import { Router } from "express";
import { query } from "../db.js";
import {
  ALLOWED_CONTENT_TYPES,
  MAX_UPLOAD_BYTES,
  createUploadUrl,
  statObject,
  publicUrlFor,
} from "../storage.js";

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
    `select id, title, artist, year, rating, created_at,
            storage_key, content_type, size_bytes
       from drawings
      order by year desc, id desc`
  );

  // An object, not a bare array. A bare array is a dead end: the day you need
  // to add a total count or a pagination cursor, there is nowhere to put it
  // that isn't a breaking change for every existing client. Stage 3 will thank
  // us for the envelope.
  res.json({ drawings: rows.map(toApiShape) });
});

// POST /api/drawings/upload-url
//
// Step 1 of 3. The browser says what it intends to upload; we decide whether
// that is allowed, choose the key, and hand back a capability.
//
// Note what this endpoint does NOT do: talk to storage, or touch the database.
// Signing is local computation, and nothing is recorded yet because nothing has
// happened yet. A signed URL that is never used costs exactly nothing.
drawingsRouter.post("/upload-url", async (req, res) => {
  const { contentType } = req.body ?? {};

  if (!ALLOWED_CONTENT_TYPES.includes(contentType)) {
    return res.status(400).json({
      error: "Unsupported content type",
      allowed: ALLOWED_CONTENT_TYPES,
    });
  }

  const { key, uploadUrl, expiresIn } = await createUploadUrl(contentType);

  // maxBytes is advisory — it lets the browser reject a huge file before
  // wasting the user's upload bandwidth. It is NOT the enforcement; the bucket
  // is. Telling the client a limit and relying on the client to honour it are
  // different things, and only the first is happening here.
  res.json({ key, uploadUrl, expiresIn, maxBytes: MAX_UPLOAD_BYTES });
});

// POST /api/drawings
//
// Step 3 of 3. Step 2 happened without us: the browser PUT the bytes straight
// to storage. Now it reports back, and we record the drawing.
//
// This is the create half of the F15 ordering: the file is already stored
// before any row exists. If this handler fails, the worst outcome is an object
// nobody references — invisible and cheap. The reverse order would risk a row
// pointing at nothing, which is a broken image in front of a user.
drawingsRouter.post("/", async (req, res) => {
  const parsed = parseDrawingInput(req.body ?? {});
  if (parsed.errors.length > 0) {
    return res.status(400).json({ error: "Invalid drawing", details: parsed.errors });
  }
  const { title, artist, year, rating, storageKey } = parsed.value;

  // Ask storage what is actually at that key.
  //
  // Everything the browser told us is a CLAIM. This is the only step that
  // consults the one party that saw the bytes. It does two jobs at once:
  //
  //   1. proves the object exists, so we never write a dangling reference
  //   2. gives us the REAL size and type, rather than the reported ones
  //
  // It also stops a client inventing a key it never uploaded to.
  const stored = await statObject(storageKey);
  if (stored === null) {
    return res.status(422).json({
      error: "No uploaded file found for that key. Upload before creating the drawing.",
    });
  }

  // Defence in depth. The bucket already enforces both of these, so reaching
  // this branch means the bucket's configuration and ours have drifted apart —
  // which is worth a 422 rather than an insert that violates a CHECK constraint
  // and surfaces as a 500.
  if (!ALLOWED_CONTENT_TYPES.includes(stored.contentType)) {
    return res.status(422).json({ error: "Stored object is not a supported image type" });
  }
  if (stored.sizeBytes > MAX_UPLOAD_BYTES) {
    return res.status(422).json({ error: "Stored object exceeds the size limit" });
  }

  try {
    const { rows } = await query(
      `insert into drawings (title, artist, year, rating, storage_key, content_type, size_bytes)
       values ($1, $2, $3, $4, $5, $6, $7)
       returning id, title, artist, year, rating, created_at,
                 storage_key, content_type, size_bytes`,
      // The values written are STORAGE's, not the client's. If the browser said
      // "2 MB JPEG" and uploaded a 40 KB PNG, the row records the PNG.
      [title, artist, year, rating, storageKey, stored.contentType, stored.sizeBytes]
    );

    // 201 Created, plus Location. Not decoration: it tells any client where the
    // thing it just made now lives, without having to construct that URL from
    // knowledge of our routing.
    res.status(201).location(`/api/drawings/${rows[0].id}`).json(rows.map(toApiShape)[0]);
  } catch (err) {
    // SQLSTATE codes are an API. Mapping the ones we can explain turns a 500
    // into an accurate answer; anything unrecognised is re-thrown so the error
    // handler logs it and returns a generic 500. Never invent a friendly
    // message for a failure you do not understand.
    if (err.code === "23505") {
      // unique_violation on storage_key: this file is already a drawing.
      return res.status(409).json({ error: "That file has already been used" });
    }
    if (err.code === "23514") {
      // check_violation: the database caught something validation missed. That
      // is the constraint doing its job, and a signal our validation has a gap.
      return res.status(400).json({ error: "Invalid drawing", constraint: err.constraint });
    }
    throw err;
  }

  // Deliberately NOT deleting the object when the insert fails.
  //
  // The tempting cleanup — delete the file if the row could not be written —
  // destroys a user's upload on any transient database error. An orphaned
  // object is harmless and sweepable; a deleted file is gone. Choose the
  // recoverable failure.
});

/**
 * Validate untrusted input at the boundary.
 *
 * Hand-written rather than a schema library, so the mechanism is visible: every
 * field is checked for presence, type, and range, and NOTHING is read out of
 * req.body except the fields named here. At real scale you would reach for zod
 * and get the same guarantees with less code — but the same guarantees.
 *
 * The bounds mirror the CHECK constraints in migrations/001. The database is
 * still the authority; this exists to produce a helpful 400 instead of letting
 * a constraint violation become a 500.
 */
function parseDrawingInput(body) {
  const errors = [];

  const title = typeof body.title === "string" ? body.title.trim() : "";
  if (title.length < 1 || title.length > 120) {
    errors.push("title must be 1-120 characters");
  }

  const artist = typeof body.artist === "string" ? body.artist.trim() : "";
  if (artist.length < 1 || artist.length > 80) {
    errors.push("artist must be 1-80 characters");
  }

  // Number.isInteger rejects "1490", 1490.5, NaN and Infinity in one call.
  // JSON gives us real types, so a string here means the client sent a string —
  // we do not coerce it, because silently accepting the wrong type is how
  // clients ship bugs that only appear at the database.
  const year = body.year;
  if (!Number.isInteger(year) || year < 1000 || year > 2100) {
    errors.push("year must be an integer between 1000 and 2100");
  }

  // Optional. Absent and null both mean "unrated" — which is NOT zero. A
  // missing rating and a rating of 0 are different facts about the world.
  let rating = null;
  if (body.rating !== undefined && body.rating !== null) {
    if (typeof body.rating !== "number" || Number.isNaN(body.rating) ||
        body.rating < 0 || body.rating > 5) {
      errors.push("rating must be a number between 0 and 5, or omitted");
    } else {
      // numeric(2,1) keeps one decimal place. Rounding here rather than letting
      // Postgres do it means the value we return is the value we stored.
      rating = Math.round(body.rating * 10) / 10;
    }
  }

  // The key must look exactly like something we minted: a UUID plus one of our
  // extensions. This is not cosmetic — it stops a client submitting "../" paths
  // or probing keys elsewhere in the bucket. Validate the SHAPE of identifiers
  // you generated, rather than assuming they came back unmodified.
  const storageKey = typeof body.storageKey === "string" ? body.storageKey : "";
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(jpg|png|webp)$/.test(storageKey)) {
    errors.push("storageKey is not a key issued by this API");
  }

  return { errors, value: { title, artist, year, rating, storageKey } };
}

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

    // The client gets a URL; the database stores a key. The join between them
    // is one environment variable, which is why changing provider or putting a
    // CDN in front never touches a row.
    //
    // Null for the seeded rows, which genuinely have no image. The frontend has
    // to handle that — "has no image yet" is a real state, not an error.
    imageUrl: row.storage_key === null ? null : publicUrlFor(row.storage_key),

    // `timestamptz` arrives as a JS Date (pg does parse this one). JSON has no
    // date type, so serialise explicitly to ISO-8601 UTC rather than relying on
    // whatever JSON.stringify happens to do with a Date.
    createdAt: row.created_at.toISOString(),
  };
}
