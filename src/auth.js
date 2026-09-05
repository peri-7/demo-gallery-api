/**
 * The middleware that turns a request into a known user, or refuses it.
 *
 * This file is where authentication (who are you) becomes authorization (are
 * you allowed) — and it is deliberately tiny, because all the thinking already
 * happened in sessions.js. Middleware is the right shape for it: the check is
 * identical for every protected route, and a rule written once in one place
 * cannot be forgotten on the fourth endpoint someone adds next year.
 *
 * WHERE THE TOKEN COMES FROM IS NOT DECIDED HERE — that is Stage 4b's whole
 * subject. For now it arrives in an `Authorization: Bearer` header, because
 * that is the form curl can produce with no browser involved, which keeps 4a
 * testable without touching a single cross-origin question. Note that
 * bearerToken() is the ONLY function that knows this. Swapping to a cookie in
 * 4b, or supporting both, means editing that one function.
 */

import { findSession } from "./sessions.js";

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
 * Attach req.auth if a valid session was presented; otherwise leave it null.
 * Never rejects. For endpoints that behave differently for a logged-in user but
 * remain open to everyone — the gallery listing, eventually.
 */
export async function attachUser(req, res, next) {
  req.auth = await findSession(bearerToken(req));
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
  const token = bearerToken(req);
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
