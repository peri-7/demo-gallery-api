/**
 * Structured logging.
 *
 * WHAT PROBLEM THIS SOLVES, AND IT IS NOT FORMATTING
 * --------------------------------------------------
 * Node serves requests concurrently, so a sequence of console.log calls is not
 * a story — it is several stories shuffled together:
 *
 *   POST /api/auth/login …
 *   RATE LIMIT login-failures: refused login ip=…
 *   POST /api/drawings …
 *   CSRF: refused POST /api/drawings from origin=…
 *
 * Which login did that refusal belong to? Nothing in the output says. The
 * information was not hidden, it was NEVER RECORDED, and no amount of clever
 * searching recovers it afterwards.
 *
 * So every line carries a reqId, stamped once per request and attached to
 * everything that request produces. That is the part you cannot retrofit.
 * JSON fields are the smaller win: `ms` as a number in a named field makes
 * "requests slower than 500ms" a filter instead of string surgery on prose.
 *
 * WHY BOTH FORMATS
 * ----------------
 * Render's free tier has no log search and no aggregation, so JSON is honestly
 * WORSE to read by eye than the string it replaces. Pretending otherwise would
 * be dishonest. Hence: pretty text where a human is watching, JSON where a
 * machine might be. LOG_FORMAT decides, defaulting by NODE_ENV.
 *
 * WHY NOT pino OR winston
 * -----------------------
 * In a real project, use one — pino especially, it is fast and boring. This is
 * ~120 lines because the mechanism is the lesson, exactly like cors.js and
 * cookies.js. A dependency here would hide the two things worth understanding:
 * how a child logger carries context, and how redaction has to work.
 */

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

const configuredLevel = process.env.LOG_LEVEL ?? "info";
if (!(configuredLevel in LEVELS)) {
  throw new Error(
    `LOG_LEVEL must be one of ${Object.keys(LEVELS).join(", ")}, got: ${configuredLevel}`
  );
}
const threshold = LEVELS[configuredLevel];

// JSON in production, readable text locally. NODE_ENV is set to "production" by
// Render automatically; LOG_FORMAT overrides for when you want to see exactly
// what production will emit without deploying.
const format = process.env.LOG_FORMAT ?? (process.env.NODE_ENV === "production" ? "json" : "pretty");

/**
 * REDACTION, BY CONSTRUCTION RATHER THAN BY REMEMBERING.
 *
 * Since Stage 4b a session credential rides along on EVERY request, in a
 * header. So the ordinary debugging instinct —
 *
 *     log.info("headers", req.headers)
 *
 * — writes live session tokens into a file that is read by more people and
 * kept longer than the database. HttpOnly stops page JavaScript from reading
 * the cookie; it does nothing whatsoever about our own server printing it.
 * That is the exact shape of QUIZ J3: HttpOnly prevents THEFT of the
 * credential, not every other way it can escape.
 *
 * The rule that makes this safe is that the check is on the KEY, applied at
 * every depth, so it cannot be forgotten at a call site. A blocklist of key
 * names is not perfect — a token stored under `{ blah: "…" }` still gets
 * through — but it catches every conventional name, and the alternative
 * (trusting each caller to remember) is what actually fails in practice.
 */
const REDACT_KEYS = new Set([
  "cookie",
  "set-cookie",
  "authorization",
  "password",
  "passwordhash",
  "password_hash",
  "token",
  "sessiontoken",
  "session_token",
  "secret",
  "database_url",
  "s3_secret_access_key",
]);

/**
 * Secrets that must be caught by VALUE, whatever key they arrived under.
 *
 * Credentials embedded in a URL are the case that matters here, because they
 * arrive in strings nobody chose to log: a Postgres error quotes the DSN it
 * failed to connect to, and that DSN contains the password.
 *
 * Written as a surgical substitution rather than a whole-string replacement.
 * The first version returned "[redacted:connection-string]" for the entire
 * value, which was safe and useless — an error whose stack has been erased
 * tells you nothing about where it came from. Keeping the scheme and host and
 * removing only `user:password@` leaves the trace diagnosable.
 *
 * Deliberately not Postgres-specific: the same shape carries credentials for
 * redis://, mongodb://, amqp:// and https:// basic-auth URLs.
 */
const SECRET_VALUE_PATTERNS = [
  { pattern: /([a-z][a-z0-9+.-]*:\/\/)[^\s:@/]+:[^\s@/]+@/gi, replacement: "$1[redacted]@" },
];

const MAX_DEPTH = 4;

function redact(value, depth = 0) {
  if (value === null || value === undefined) return value;

  if (typeof value === "string") {
    let out = value;
    for (const { pattern, replacement } of SECRET_VALUE_PATTERNS) {
      out = out.replace(pattern, replacement);
    }
    return out;
  }

  if (typeof value !== "object") return value;

  // Depth cap, not paranoia: a Postgres error object has circular references
  // and a request object reaches the whole socket. Left unbounded, one log
  // call serialises the universe or throws.
  if (depth >= MAX_DEPTH) return "[truncated:depth]";

  if (Array.isArray(value)) return value.map((item) => redact(item, depth + 1));

  // Errors do not serialise: JSON.stringify(new Error("x")) is "{}", which is
  // the single most common way a log line ends up saying nothing at all.
  if (value instanceof Error) {
    return {
      name: value.name,
      message: redact(value.message, depth + 1),
      code: value.code,
      // THE STACK GOES THROUGH REDACTION TOO, and this is not belt-and-braces.
      // A stack trace BEGINS WITH THE MESSAGE:
      //
      //   Error: could not connect to postgresql://user:hunter2@…
      //       at connect (…)
      //
      // So redacting `message` alone produced a line reading
      // message="[redacted:connection-string]" directly above a stack quoting
      // the password in full. The first version of this file did exactly that,
      // and scripts/check-logging.mjs is what caught it.
      //
      // The general lesson is worth more than the fix: REDACTING ONE COPY OF A
      // SECRET IS NOT REDACTING THE SECRET. Data gets duplicated into derived
      // fields — stacks, summaries, error `cause` chains — and every copy needs
      // the same treatment or the effort was theatre.
      stack: redact(value.stack, depth + 1),
      // Node 16.9+ chains errors through `cause`, and a cause is another Error
      // carrying its own message and stack. Missing it would leak by exactly
      // the route above, one level down.
      cause: value.cause === undefined ? undefined : redact(value.cause, depth + 1),
    };
  }

  const out = {};
  for (const [key, item] of Object.entries(value)) {
    out[key] = REDACT_KEYS.has(key.toLowerCase()) ? "[redacted]" : redact(item, depth + 1);
  }
  return out;
}

function emit(level, msg, fields) {
  if (LEVELS[level] < threshold) return;

  const record = { level, time: new Date().toISOString(), msg };

  // Absent fields are omitted, not printed as the string "undefined". Most
  // request lines have no Origin and no X-Forwarded-For, and `origin=undefined`
  // on every one of them is noise that reads like a bug. JSON.stringify drops
  // undefined on its own, so without this the two formats would disagree —
  // and a log you cannot reproduce locally is worth less than one you can.
  for (const [key, value] of Object.entries(redact(fields) ?? {})) {
    if (value !== undefined) record[key] = value;
  }

  // warn and error go to stderr. Not decoration: it is what lets a platform,
  // a shell redirect or a supervisor separate "something happened" from
  // "everything is fine", without parsing anything.
  const stream = LEVELS[level] >= LEVELS.warn ? process.stderr : process.stdout;

  if (format === "json") {
    // One object per line — "JSON Lines". A log is append-only and read a line
    // at a time, so a single enormous JSON array would be unparseable until
    // the process exited.
    stream.write(JSON.stringify(record) + "\n");
    return;
  }

  // Pretty: put the human-relevant fields first and the rest as key=value.
  const { level: _l, time, msg: _m, reqId, ...rest } = record;
  const head = `${time.slice(11, 23)} ${level.toUpperCase().padEnd(5)}` + (reqId ? ` [${reqId}]` : "");
  const tail = Object.entries(rest)
    .map(([k, v]) => `${k}=${typeof v === "object" && v !== null ? JSON.stringify(v) : v}`)
    .join(" ");
  stream.write(`${head} ${msg}${tail ? " " + tail : ""}\n`);
}

/**
 * A logger, optionally carrying fields that are added to every line it writes.
 *
 * child() is the whole reason this is not four loose functions. Once a request
 * has an id, every log call inside that request should carry it — and threading
 * it through every function signature by hand is the kind of chore that gets
 * skipped exactly when it matters. So the request handler gets its own logger
 * with reqId already baked in.
 */
function makeLogger(context = {}) {
  return {
    debug: (msg, fields) => emit("debug", msg, { ...context, ...fields }),
    info: (msg, fields) => emit("info", msg, { ...context, ...fields }),
    warn: (msg, fields) => emit("warn", msg, { ...context, ...fields }),
    error: (msg, fields) => emit("error", msg, { ...context, ...fields }),
    child: (extra) => makeLogger({ ...context, ...extra }),
  };
}

export const logger = makeLogger();

// Exported so the check script can demonstrate redaction without a server, and
// so index.js can report its own configuration at boot.
export const logConfig = { level: configuredLevel, format };
export const _redact = redact;
