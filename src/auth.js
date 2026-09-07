/**
 * The middleware that turns a request into a known user, or refuses it.
 *
 * This file is where authentication (who are you) becomes authorization (are
 * you allowed) — and it is deliberately tiny, because all the thinking already
 * happened in sessions.js. Middleware is the right shape for it: the check is
 * identical for every protected route, and a rule written once in one place
 * cannot be forgotten on the fourth endpoint someone adds next year.
 *
 * WHERE THE TOKEN COMES FROM IS DECIDED HERE, AND ONLY HERE.
 *
 * Stage 4a said this was the seam Stage 4b would move, and this is the move.
 * Everything downstream — findSession, requireAuth, the route guards, the
 * sessions table, the sha256 lookup — is unchanged and indifferent. The token
 * is the same 43-character string it always was. Only its transport changed.
 *
 * That is worth noticing as a design result, not a coincidence: the reason this
 * stage is a two-function edit rather than a rewrite is that 4a refused to let
 * knowledge of HTTP leak into sessions.js.
 */

import { findSession } from "./sessions.js";
import { parseCookies, SESSION_COOKIE } from "./cookies.js";

/**
 * Pull the token out of `Authorization: Bearer <token>`.
 *
 * Returns null for anything else, including a missing header, a different
 * scheme (Basic, Digest), or a malformed one. Never throws — a garbled header
 * is a request from a stranger, not a server fault.
 */
export function bearerToken(req) {
  const header = req.headers.authorization;
  if (typeof header !== "string") return null;

  // The scheme is case-insensitive per RFC 9110 ("Bearer", "bearer", "BEARER"
  // are the same token). Being strict here would produce a 401 that is
  // impossible to debug from the client side, for no security benefit.
  const match = /^bearer[ ]+(.+)$/i.exec(header.trim());
  return match ? match[1] : null;
}

/**
 * Pull the token out of the session cookie.
 */
export function cookieToken(req) {
  const value = parseCookies(req)[SESSION_COOKIE];
  return typeof value === "string" && value !== "" ? value : null;
}

/**
 * The one place that decides how a session is presented.
 *
 * COOKIE FIRST, THEN Authorization. Two questions worth answering about that:
 *
 * WHY SUPPORT BOTH? The cookie is for browsers, where HttpOnly is the point.
 * The header is for everything that has no cookie jar — curl, our own check
 * scripts, a future mobile app. Dropping it would mean every script in
 * scripts/ has to manage a cookie file to test an endpoint.
 *
 * DOES ACCEPTING BOTH WEAKEN ANYTHING? No, and the reason is precise: CSRF
 * works because the browser attaches the cookie AUTOMATICALLY. There is no
 * equivalent for Authorization — an attacker's page cannot make the browser add
 * a header it did not write, and writing it requires a preflight our allowlist
 * refuses. So the header path adds no ambient authority. The cookie is the only
 * risky transport, and csrf.js covers it.
 *
 * The ORDER matters though. Preferring the cookie means a browser session
 * cannot be silently overridden by an attacker-supplied Authorization header on
 * a request our own page made — a narrow case, but the cheap choice is the safe
 * one, and "whichever we found first" is not a decision anyone should have to
 * reconstruct later.
 */
export function sessionToken(req) {
  return cookieToken(req) ?? bearerToken(req);
}

/**
 * Attach req.auth if a valid session was presented; otherwise leave it null.
 * Never rejects. For endpoints that behave differently for a logged-in user but
 * remain open to everyone — the gallery listing, eventually.
 */
export async function attachUser(req, res, next) {
  req.auth = await findSession(sessionToken(req));
  next();
}

/**
 * Reject the request unless a valid session was presented.
 *
 * Async, with no try/catch. In Express 5 a rejected promise from a handler or
 * middleware is forwarded to the error handler automatically — the change that
 * made all those try/catch wrappers in old tutorials unnecessary (QUIZ.md E11).
 * In Express 4 this exact function would hang the request forever on a database
 * error.
 */
export async function requireAuth(req, res, next) {
  const token = sessionToken(req);
  const auth = token === null ? null : await findSession(token);

  if (auth === null) {
    // 401, not 403, and the distinction is not pedantry:
    //
    //   401 Unauthorized — I do not know who you are. Log in and try again.
    //   403 Forbidden    — I know exactly who you are, and the answer is no.
    //
    // They imply different things for the client: a 401 means show the login
    // form, a 403 means showing the login form is useless and possibly
    // insulting. (QUIZ.md E9.)
    //
    // WWW-Authenticate is what makes 401 a real 401 rather than a number: the
    // spec requires it, and it names the scheme the client should use.
    res.setHeader("WWW-Authenticate", 'Bearer realm="api"');

    // One message for every cause: no header, wrong scheme, unknown token,
    // expired token, deleted session, deleted user. The client can do nothing
    // differently for any of them, and distinguishing them turns the endpoint
    // into an oracle for probing which tokens once existed.
    return res.status(401).json({ error: "Authentication required" });
  }

  // From here on, every downstream handler can rely on req.auth.user existing.
  // That is the actual product of this middleware: a guarantee, not a check.
  req.auth = auth;
  next();
}
