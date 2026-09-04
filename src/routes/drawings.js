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

// The sort allowlist.
//
// A column name is SYNTAX, not a value, so it can never be a bound parameter:
// `order by $1` does not sort by the column you name — Postgres parses the
// statement before the parameters arrive, sees a constant, and sorts by
// nothing. Silently. No error, wrong answer.
//
// That rules out the defence we use everywhere else, so sorting needs a
// different one. The client's string is never escaped, never sanitised, and
// never concatenated into SQL. It is a KEY INTO THIS MAP. What reaches the
// query is our value; theirs only ever chose between things we already wrote.
//
// `sort=year); drop table drawings--` is not dangerous here because it is not
// dangerous anywhere: it simply isn't a key, and the request is a 400.
const SORTS = {
  // nullable matters for more than correctness — see buildOrderBy.
  year: { column: "year", nullable: false },
  rating: { column: "rating", nullable: true },
  created_at: { column: "created_at", nullable: false },
};

const ORDERS = ["asc", "desc"];

const DEFAULT_SORT = "year";
const DEFAULT_ORDER = "desc";

/**
 * Build the ORDER BY clause from an already-validated sort key.
 *
 * Every fragment here comes from SORTS or from a two-element literal list. No
 * caller-supplied character reaches the SQL string. That is the only reason a
 * template literal is acceptable in a query at all, and it is worth being
 * suspicious of every other one you ever see.
 */
function buildOrderBy(sort, order) {
  const { column, nullable } = SORTS[sort];

  // The tiebreaker follows the same direction as the main key. Without `id`,
  // rows sharing a year have NO defined order — two identical requests may
  // return them differently, and pagination built on that is broken from the
  // start. See the index in migrations/001, which was created with this in mind.
  const tiebreak = `id ${order}`;

  if (!nullable) return `order by ${column} ${order}, ${tiebreak}`;

  // Nulls need an explicit position, for two separate reasons.
  //
  // MEANING: Postgres's default is nulls-first when descending and nulls-last
  // when ascending — i.e. NULL is treated as the LARGEST value. For a rating,
  // that puts every unrated drawing above the 5-star ones. We want the
  // opposite: unrated sorts below everything.
  //
  // PERFORMANCE: an index records a null position too. migrations/001 created
  // (rating desc nulls last, id desc). A query asking for `nulls first` cannot
  // use it, and a query asking for ascending order uses it by scanning
  // BACKWARDS — which yields `rating asc nulls first`. So the clause below is
  // not just our preferred meaning, it is the one shape that stays indexed in
  // both directions. Sort order and index definition are one decision, not two.
  const nulls = order === "desc" ? "nulls last" : "nulls first";
  return `order by ${column} ${order} ${nulls}, ${tiebreak}`;
}

/**
 * Build the WHERE clause and its parameter list together.
 *
 * Unlike ORDER BY, the number of conditions varies per request, and that is the
 * whole difficulty. The SQL text and the values array must stay in lockstep: if
 * a clause says `$3` and the third element of the array is something else, the
 * query does not fail — it silently returns the wrong rows. A test with one
 * filter would pass and a request with three would quietly lie.
 *
 * The trick that makes drift impossible: never write a placeholder number by
 * hand. Push the value first, then derive the number from the array's new
 * length. The two cannot disagree because one is computed from the other.
 *
 * Note what is NOT happening: no caller-supplied character reaches the SQL
 * string. Values go in the array; the string is only ever assembled from our
 * own column names plus a number we counted.
 */
function buildWhere(filters) {
  const clauses = [];
  const params = [];

  if (filters.year !== undefined) {
    params.push(filters.year);
    clauses.push(`year = $${params.length}`);
  }

  if (filters.minRating !== undefined) {
    // A NULL rating fails this comparison rather than matching it — `null >= 4`
    // is NULL, not false, and WHERE keeps only rows that are true. That is the
    // behaviour we want (unrated is not "at least 4"), but it is worth knowing
    // it happened by three-valued logic rather than by a check we wrote.
    params.push(filters.minRating);
    clauses.push(`rating >= $${params.length}`);
  }

  if (filters.artist !== undefined) {
    // The wildcards are concatenated INSIDE the query, around a bound value —
    // not glued onto the string in JavaScript. Either produces the same match,
    // but this way the value never touches the SQL text, so there is nothing to
    // reason about. Make the safe thing the habit, not the special case.
    //
    // ilike is case-insensitive. Honest cost: a leading % means no btree index
    // can help, so this is a sequential scan over every row. Fine at eight
    // rows, wrong at a million — the real fix there is a trigram index
    // (pg_trgm), which is a different tool, not a bigger version of this one.
    params.push(filters.artist);
    clauses.push(`artist ilike '%' || $${params.length} || '%'`);
  }

  if (filters.hasImage !== undefined) {
    // No parameter at all: the value chooses between two fixed SQL fragments,
    // the same allowlist technique as sorting. `is not null` cannot be a bound
    // value any more than a column name can.
    clauses.push(filters.hasImage ? "storage_key is not null" : "storage_key is null");
  }

  // No filters means no WHERE clause at all, not `where true`. Keep the SQL you
  // send the same shape as the SQL you would have written by hand.
  const sql = clauses.length === 0 ? "" : `where ${clauses.join(" and ")}`;
  return { sql, params };
}

/**
 * Parse one query-string value that is supposed to be a number.
 *
 * A query string can only express STRINGS. `?year=1889` arrives as "1889" and
 * there is no encoding in which it could arrive as the number 1889 — so unlike
 * the JSON body, where we refuse to coerce "2026" and return a 400, here
 * conversion is mandatory.
 *
 * That is not a contradiction. The rule was never "never coerce"; it is "know
 * what your transport can express, and reject anything it can express that you
 * did not mean". JSON has real types, so a string year is a client bug. A query
 * string has no types, so a string year is the only thing possible.
 *
 * Number() rather than parseInt(), deliberately: parseInt("12abc") returns 12
 * and parseInt("1e3") returns 1. The regex settles the shape first and Number
 * then converts something already known to be a clean numeral.
 */
function parseNumber(raw, { integer }) {
  if (typeof raw !== "string") return null;
  const pattern = integer ? /^\d+$/ : /^\d+(\.\d+)?$/;
  if (!pattern.test(raw)) return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

/**
 * Validate the query string.
 *
 * `?sort=year` looks like configuration rather than input because it sits in
 * the URL bar, but it arrives from the same untrusted place as a JSON body: a
 * caller we did not write. Same treatment.
 *
 * One trap specific to query strings. Express parses `?sort=year&sort=rating`
 * into the ARRAY ["year", "rating"], not a string — a client can change the
 * TYPE of a parameter just by repeating it. Every field below is therefore
 * checked with typeof before anything else touches it. `req.query.sort
 * .toLowerCase()` would crash on that input, and a crash driven by a URL a
 * stranger chose is a denial of service, not a typo.
 */
function parseListQuery(q) {
  const errors = [];

  // Absent is not invalid — these are optional with documented defaults.
  // Present-but-wrong IS invalid, and gets a 400 rather than a silent fallback
  // to the default. Silently ignoring a parameter you don't understand means a
  // client asking for `?sort=titel` gets a normal-looking response sorted by
  // something else entirely, and nothing anywhere reports the typo.
  const sort = q.sort === undefined ? DEFAULT_SORT : q.sort;
  if (typeof sort !== "string" || !Object.hasOwn(SORTS, sort)) {
    errors.push(`sort must be one of: ${Object.keys(SORTS).join(", ")}`);
  }

  const order = q.order === undefined ? DEFAULT_ORDER : q.order;
  if (typeof order !== "string" || !ORDERS.includes(order)) {
    errors.push(`order must be one of: ${ORDERS.join(", ")}`);
  }

  // --- filters, all optional -------------------------------------------
  //
  // `undefined` means "the caller did not filter on this" and is left out of
  // the WHERE clause entirely. That is different from a value we rejected,
  // which is an error — never a silently-dropped filter. A search that quietly
  // ignores half your criteria and returns confident-looking results is worse
  // than one that fails.
  const filters = {};

  if (q.year !== undefined) {
    const year = parseNumber(q.year, { integer: true });
    // Same bounds as the CHECK constraint in migrations/001. Not because the
    // database would be harmed by year=99999 — no row can match it — but
    // because a query outside the possible range is certainly a mistake, and
    // saying so beats returning an empty list that looks like a real answer.
    if (year === null || year < 1000 || year > 2100) {
      errors.push("year must be an integer between 1000 and 2100");
    } else {
      filters.year = year;
    }
  }

  if (q.minRating !== undefined) {
    const minRating = parseNumber(q.minRating, { integer: false });
    if (minRating === null || minRating < 0 || minRating > 5) {
      errors.push("minRating must be a number between 0 and 5");
    } else {
      filters.minRating = minRating;
    }
  }

  if (q.artist !== undefined) {
    // Bounded on purpose. An unbounded search term is an unbounded pattern for
    // the database to match against every row — the length limit is as much a
    // resource control as a validation rule.
    const artist = typeof q.artist === "string" ? q.artist.trim() : "";
    if (artist.length < 1 || artist.length > 80) {
      errors.push("artist must be 1-80 characters");
    } else {
      filters.artist = artist;
    }
  }

  if (q.hasImage !== undefined) {
    // "true"/"false" as strings, because a query string has no booleans. Note
    // what is NOT used here: Boolean(q.hasImage), which returns true for the
    // string "false" — one of the most reliable ways to ship a filter that
    // does the opposite of what it says.
    if (q.hasImage !== "true" && q.hasImage !== "false") {
      errors.push('hasImage must be "true" or "false"');
    } else {
      filters.hasImage = q.hasImage === "true";
    }
  }

  return { errors, value: { sort, order, filters } };
}

// GET /api/drawings?sort=year&order=desc
//
// No try/catch. Express 5 detects that the handler returned a promise and
// forwards a rejection to the error-handling middleware automatically. In
// Express 4 this was the single most common source of hung requests: an async
// handler that threw would reject silently, the response was never sent, and
// the browser just waited. Worth knowing, because most tutorials online still
// wrap everything in try/catch for a version you are not running.
drawingsRouter.get("/", async (req, res) => {
  const parsed = parseListQuery(req.query);
  if (parsed.errors.length > 0) {
    return res.status(400).json({ error: "Invalid query", details: parsed.errors });
  }
  const { sort, order, filters } = parsed.value;

  const where = buildWhere(filters);

  const { rows } = await query(
    `select id, title, artist, year, rating, created_at,
            storage_key, content_type, size_bytes
       from drawings
      ${where.sql}
      ${buildOrderBy(sort, order)}`,
    where.params
  );

  // An object, not a bare array — and this is the stage where that pays off.
  // Echoing back what was actually applied means a client never has to assume
  // its request was honoured, and a total count or a cursor can be added later
  // without breaking a single existing caller. A bare array had nowhere to put
  // any of this.
  res.json({ drawings: rows.map(toApiShape), sort, order, filters });
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
