/**
 * The four endpoints that make a login work.
 *
 *   POST /api/auth/signup   create a user
 *   POST /api/auth/login    exchange a password for a session token
 *   POST /api/auth/logout   destroy the session
 *   GET  /api/auth/me       who am I
 *
 * All four are POST except the last, and that is not decoration: login and
 * logout CHANGE SERVER STATE (they create and delete rows), and a GET is
 * supposed to be safe — repeatable, cacheable, prefetchable, safe for a browser
 * to follow speculatively. `GET /logout` is a classic bug: a link prefetcher or
 * an <img src> logs the user out, and nobody can work out why.
 */

import { Router } from "express";
import { randomBytes } from "node:crypto";
import { query } from "../db.js";
import {
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH,
  hashPassword,
  verifyPassword,
  needsRehash,
} from "../password.js";
import { createSession, destroySession } from "../sessions.js";
import { requireAuth, sessionToken } from "../auth.js";
import { setSessionCookie, clearSessionCookie } from "../cookies.js";
import { SlidingWindow, rateLimit } from "../ratelimit.js";

export const authRouter = Router();

// ---------------------------------------------------------------------------
// Rate limits
// ---------------------------------------------------------------------------

/**
 * TWO LIMITERS, BECAUSE EITHER ONE ALONE HAS A DEFEAT.
 *
 * Per-IP alone loses to a botnet: ten thousand hosts each making three
 * attempts is thirty thousand guesses and no host is near its limit. This is
 * credential stuffing and it is how the attack is actually run today.
 *
 * Per-email alone is worse in a different direction — it lets an attacker LOCK
 * A REAL USER OUT of their own account by deliberately failing five logins
 * against their address. The defence becomes the attack. This is a genuine
 * design problem with no clean answer, and the mitigations are:
 *
 *   1. Count only FAILURES. A user who types their password correctly is never
 *      affected no matter how much noise someone else makes.
 *   2. Clear the count on a successful login, so a legitimate sign-in from
 *      anywhere ends the lockout immediately.
 *   3. Keep the window short. Fifteen minutes of denial is an annoyance;
 *      permanent lockout requiring support is a real outage.
 *
 * That still leaves a victim who cannot log in for fifteen minutes while being
 * actively targeted. It is the accepted trade: a bounded annoyance for them,
 * against unbounded guessing at their password.
 */
const authIpLimit = new SlidingWindow({
  name: "auth-ip",
  windowMs: 15 * 60_000,
  max: Number.parseInt(process.env.RATE_LIMIT_AUTH_PER_IP ?? "20", 10),
});

const loginFailureLimit = new SlidingWindow({
  name: "login-failures-per-email",
  windowMs: 15 * 60_000,
  max: Number.parseInt(process.env.RATE_LIMIT_LOGIN_FAILURES ?? "5", 10),
});

/**
 * Applied to signup and login only — NOT to /me or /logout.
 *
 * The reason is cost, and it is the reason the limiter exists at all. Signup
 * and login each run one scrypt hash: 300ms of CPU and 16 MiB on Render. /me is
 * a sha256 and one indexed SELECT — microseconds. Limiting it would break the
 * page-load session check for a user with several tabs open while defending
 * nothing.
 *
 * Limit where the work is, not uniformly. A limit that is not aimed at a cost
 * is just a smaller product.
 */
const limitAuthByIp = rateLimit(authIpLimit);

/**
 * A real hash of a password nobody knows, computed once at boot.
 *
 * This exists purely to burn the correct amount of time when the email does not
 * exist — see the login handler. Generated rather than hard-coded so it always
 * uses today's cost parameters: a frozen constant would silently stop matching
 * the real work as soon as N was raised, and the timing leak would quietly
 * reopen.
 *
 * Top-level await delays boot by one hash (~35ms). Paid once, at startup, never
 * per request.
 */
const DUMMY_HASH = await hashPassword(randomBytes(32).toString("hex"));

// ---------------------------------------------------------------------------
// Validation at the boundary
// ---------------------------------------------------------------------------

/**
 * Note what is NOT here: a clever email regex.
 *
 * The grammar for a valid address is genuinely baroque (quoted strings,
 * comments, IP literals are all legal), and every "perfect" regex on the
 * internet rejects addresses that work. More to the point, syntax is not the
 * property anyone cares about: `nobody@example.com` is perfectly well-formed
 * and completely fake. THE ONLY REAL VALIDATION IS SENDING AN EMAIL AND SEEING
 * IF SOMEONE CLICKS. Everything here is a cheap typo-catcher, so it should be
 * loose enough never to reject a real address.
 */
function parseCredentials(body) {
  const errors = [];

  // typeof checks first, before touching a single method. A JSON body can
  // contain an array, an object or null where a string was expected, and
  // `body.email.trim()` on any of them is a 500 handed to a stranger — the
  // same lesson as the repeated query parameter in QUIZ.md H3, arriving
  // through a different door.
  const rawEmail = body?.email;
  const rawPassword = body?.password;

  let email = null;
  if (typeof rawEmail !== "string") {
    errors.push("email must be a string");
  } else {
    // Normalised on the way in: trimmed and lowercased, so the stored value
    // matches what the unique index on lower(email) enforces. Users type stray
    // spaces and capital letters; neither should create a second account.
    email = rawEmail.trim().toLowerCase();
    if (email.length < 3 || email.length > 254) {
      errors.push("email must be between 3 and 254 characters");
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errors.push("email does not look like an address");
    }
  }

  let password = null;
  if (typeof rawPassword !== "string") {
    errors.push("password must be a string");
  } else {
    // NOT trimmed. A space is a legitimate character in a password, and
    // trimming would silently change what the user typed — so a password that
    // ends in a space would be accepted at signup and rejected at login, or
    // worse, accepted at both while being a different string than they think.
    password = rawPassword;
    if (password.length < MIN_PASSWORD_LENGTH) {
      errors.push(`password must be at least ${MIN_PASSWORD_LENGTH} characters`);
    } else if (password.length > MAX_PASSWORD_LENGTH) {
      errors.push(`password must be at most ${MAX_PASSWORD_LENGTH} characters`);
    }
  }

  return { errors, value: { email, password } };
}

// ---------------------------------------------------------------------------
// POST /api/auth/signup
// ---------------------------------------------------------------------------

authRouter.post("/signup", limitAuthByIp, async (req, res) => {
  const parsed = parseCredentials(req.body ?? {});
  if (parsed.errors.length > 0) {
    // Signup is the one place where telling the user exactly what is wrong is
    // right: they are creating the value, they need to fix it, and none of it
    // is a secret. Login is the opposite case — see below.
    return res.status(400).json({ error: "Invalid credentials", details: parsed.errors });
  }
  const { email, password } = parsed.value;

  const passwordHash = await hashPassword(password);

  // INSERT AND CATCH, rather than SELECT-then-INSERT.
  //
  // "Check whether the email is taken, then insert if it isn't" is a
  // time-of-check-to-time-of-use race: two signups for the same address can
  // both find nothing and both proceed. The window is small and the internet is
  // large. Worse, writing it that way means the correctness of your data
  // depends on application code winning a race, when the database already has a
  // primitive that cannot lose one.
  //
  // The unique index IS the check. Attempt the write and let Postgres arbitrate.
  try {
    const result = await query(
      `insert into users (email, password_hash)
       values ($1, $2)
       returning id, email, created_at`,
      [email, passwordHash]
    );

    const user = result.rows[0];
    // 201 Created, with no session. Signing up and logging in are separate
    // ideas here so each endpoint does exactly one thing; a production app
    // would usually issue a session immediately to save the user a step.
    return res.status(201).json({
      user: { id: user.id, email: user.email, createdAt: user.created_at },
    });
  } catch (err) {
    // 23505 is unique_violation. Matching on the SQLSTATE code, never on the
    // message text: codes are a stable contract, messages are prose that
    // changes between Postgres versions and locales.
    if (err.code === "23505") {
      // This response admits the address is taken, and that IS an account
      // enumeration leak: anyone can discover who has an account here.
      //
      // It is deliberate, because the honest alternatives are worse for a
      // project without email delivery. Real mitigation is to answer 202 to
      // every signup and send a mail that either says "confirm your account" or
      // "you already have one" — the difference is then visible only to whoever
      // owns the inbox. That needs an email provider, so it is out of scope
      // here and listed in CLAUDE.md as a known shortcut rather than pretended
      // away.
      return res.status(409).json({ error: "That email is already registered" });
    }
    throw err; // anything else is a real fault: Express 5 forwards it to the 500 handler
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/login
// ---------------------------------------------------------------------------

authRouter.post("/login", limitAuthByIp, async (req, res) => {
  const parsed = parseCredentials(req.body ?? {});
  if (parsed.errors.length > 0) {
    // Note the difference from signup: no `details`. Once an account might
    // exist, field-level feedback starts describing the stored value. A
    // response of "password must be at least 10 characters" to a 6-character
    // guess tells an attacker something about the shape of real passwords here.
    return res.status(400).json({ error: "Invalid credentials" });
  }
  const { email, password } = parsed.value;

  /**
   * THE FAILURE CHECK GOES HERE — BEFORE THE HASH, NOT AFTER.
   *
   * This is the whole point of the exercise. Checking after verifyPassword
   * would refuse the request having already spent the 300ms and 16 MiB we were
   * trying to protect. A limiter placed after the cost is not a limiter, it is
   * a status code.
   *
   * Note that it does NOT reopen the enumeration leak Stage 4a closed. Reaching
   * this 429 requires having already sent five failed attempts for this exact
   * address, so it tells an attacker only what they already knew. Crucially, we
   * record failures for addresses that DO NOT EXIST too (see below) — if we
   * only counted real accounts, "did I get rate limited?" would become a
   * perfect account-existence oracle, and this fast path would have undone the
   * dummy-hash work three lines below it.
   */
  const failureState = loginFailureLimit.check(email);
  if (!failureState.allowed) {
    const retryAfter = Math.max(1, Math.ceil(failureState.retryAfterMs / 1000));
    res.setHeader("Retry-After", String(retryAfter));
    // The email is NOT logged. It is not a secret the way a password is, but
    // logs are read by more people and kept longer than the database, and
    // "which addresses are under attack" is exactly the list an attacker wants.
    // The IP is what an operator actually needs to act on.
    console.warn(`RATE LIMIT login-failures: refused login ip=${req.ip} retryAfter=${retryAfter}s`);
    return res.status(429).json({
      error: "Too many failed sign-in attempts. Try again later.",
      retryAfterSeconds: retryAfter,
    });
  }

  // lower(email) on both sides, matching users_email_lower_key exactly. Written
  // any other way — `where email = $1` — this is a sequential scan that also
  // fails to find users whose stored address differs in case.
  const found = await query(
    `select id, email, password_hash from users where lower(email) = lower($1)`,
    [email]
  );
  const user = found.rows[0] ?? null;

  // THE DELIBERATE WASTE OF 35 MILLISECONDS.
  //
  // The obvious code returns immediately when no user matches. That is a
  // TIMING ORACLE: a request for a real address takes ~35ms (a scrypt hash),
  // one for an unknown address takes ~2ms (no hash at all). The difference is
  // enormous, trivially measurable over the network, and lets anyone check
  // whether an address has an account here without ever guessing a password.
  //
  // So when there is no user, we hash the submitted password against a dummy
  // record anyway and throw the answer away. Both paths do the same work, so
  // both take the same time, and the response carries no information the
  // attacker did not already have.
  //
  // Constant-time thinking applies to whole request paths, not just to
  // byte comparisons.
  const ok = user
    ? await verifyPassword(password, user.password_hash)
    : (await verifyPassword(password, DUMMY_HASH), false);

  if (!ok) {
    // Recorded on EVERY failure, including one for an address with no account.
    // Counting only real users would make the limiter itself the enumeration
    // oracle that the dummy hash above exists to prevent — the sixth attempt
    // returning 429 instead of 401 would answer "does this account exist?"
    // exactly. The limiter must be as blind as the error message.
    loginFailureLimit.record(email);

    // ONE message for "no such account" and "wrong password".
    //
    // Splitting them is the single most common authentication mistake, and it
    // is worth being precise about why: it halves the attacker's problem. With
    // separate messages, guessing consists of (1) find valid addresses, cheaply
    // and without any password attempts, then (2) attack only those. With one
    // message, every guess must be an address AND a password simultaneously.
    return res.status(401).json({ error: "Invalid email or password" });
  }

  // Correct password: forget the failures. Mitigation (2) from the block at the
  // top of this file — someone who mistypes four times and then succeeds starts
  // clean rather than carrying a nearly-full budget for fifteen minutes.
  //
  // Be precise about what this does NOT do. Once the limit is already reached
  // we return 429 above WITHOUT verifying the password, so a locked-out user
  // cannot clear it by logging in correctly — there is no path to this line.
  // Knowing your own password does not end an active lockout; only time does.
  // That is the residual cost of the per-email limiter, and it is real.
  loginFailureLimit.reset(email);

  // Correct password. This is the ONLY moment the plaintext is legitimately in
  // memory, so it is the only moment the stored hash can be upgraded to a
  // higher cost. Failing to do this is why applications end up with rows still
  // protected by parameters chosen a decade ago.
  if (needsRehash(user.password_hash)) {
    await query("update users set password_hash = $1 where id = $2", [
      await hashPassword(password),
      user.id,
    ]);
  }

  // A fresh session every login. Never reuse or extend an existing one: each
  // login is a separate device with its own lifetime, and "log out this
  // device" is only meaningful if devices have separate rows.
  const session = await createSession(user.id);

  // Stage 4b: the token leaves in a Set-Cookie header instead of the body.
  setSessionCookie(res, session.token, session.expiresAt);

  res.json({
    // NOTE WHAT IS NO LONGER HERE: `token`.
    //
    // Returning it as well would quietly defeat the entire point of HttpOnly.
    // The cookie is unreadable to page JavaScript — but a token in the response
    // body is readable by whatever called fetch(), so any XSS payload that can
    // trigger a login response can read it, and any client that receives it is
    // tempted to stash it somewhere attackable. A credential the browser
    // manages must not also be handed to the code we were protecting it from.
    //
    // Non-browser clients are unaffected: curl reads Set-Cookie like any other
    // header (`curl -c jar`), and scripts/ now does exactly that.
    expiresAt: session.expiresAt,
    user: { id: user.id, email: user.email },
  });
});

// ---------------------------------------------------------------------------
// POST /api/auth/logout
// ---------------------------------------------------------------------------

authRouter.post("/logout", async (req, res) => {
  // No requireAuth. Logging out is not a privilege — it deletes a row that the
  // caller must already possess the token for, so demanding a valid session
  // first only means an expired token produces a 401 instead of doing the
  // obvious thing.
  await destroySession(sessionToken(req));

  // Clear the cookie too. The DELETE above is what actually ends the session —
  // the row is the authority, exactly as in Stage 4a — but leaving the cookie in
  // place would mean the browser keeps sending a string that names nothing, and
  // every subsequent request pays a pointless database lookup to be told 401.
  //
  // The attributes must match the ones it was set with or the browser treats it
  // as a different cookie and leaves the original alone. See cookies.js.
  clearSessionCookie(res);

  // 204 unconditionally, whether a row was deleted or not. There is nothing
  // for a client to do differently, and reporting the difference would confirm
  // whether a token was live — a probe worth answering with silence.
  //
  // 204 No Content: the operation succeeded and there is deliberately no body.
  res.status(204).end();
});

// ---------------------------------------------------------------------------
// GET /api/auth/me
// ---------------------------------------------------------------------------

// The endpoint a frontend calls on page load to answer "am I logged in?".
//
// It has to exist because the client CANNOT ANSWER THAT QUESTION ITSELF. It may
// hold a token, but only the server knows whether the row still exists, whether
// it expired, or whether the account was deleted an hour ago. "Logged in" is
// always the server's opinion, asked freshly.
authRouter.get("/me", requireAuth, (req, res) => {
  res.json({
    user: req.auth.user,
    session: {
      createdAt: req.auth.session.createdAt,
      expiresAt: req.auth.session.expiresAt,
    },
  });
});
