/**
 * CSRF: the bill that arrives with cookies.
 *
 * THE ATTACK, CONCRETELY
 * ----------------------
 * A user is logged into our gallery. In another tab they open evil.example,
 * which serves this:
 *
 *     <form action="https://demo-gallery-api.onrender.com/api/drawings"
 *           method="POST">
 *       <input name="title" value="...">
 *     </form>
 *     <script>document.forms[0].submit()</script>
 *
 * The browser sends that request to our API and — because cookies are attached
 * BY DESTINATION, not by who asked — helpfully includes the session cookie. Our
 * server sees a perfectly valid session and does the thing.
 *
 * Nothing was stolen. The attacker never saw the cookie, never read the
 * response (CORS stops that), and does not know who the user is. They simply
 * caused an authenticated request to happen. "Cross-Site Request FORGERY" is a
 * slightly misleading name: nothing is forged. The browser is behaving exactly
 * as designed, and the design is the problem.
 *
 * WHY WE HAVE NO CHOICE ABOUT SameSite
 * ------------------------------------
 * SameSite=Lax would stop this outright — that is what it is for, and it is
 * why browsers made it the default. We cannot use it. Our client is on
 * vercel.app and our API on onrender.com, so EVERY request from our own client
 * is already cross-site; Lax would refuse to attach the cookie to any of them
 * and nothing would work. Choosing SameSite=None to make our own app function
 * is precisely what re-opens the door for evil.example.
 *
 * A same-site deployment (app.example.com + api.example.com) gets this defence
 * free from the browser. Ours has to build it. That is the concrete, tangible
 * cost of the two-hostname architecture, and it is worth having felt.
 *
 * WHY AN Origin CHECK IS THE DEFENCE
 * ----------------------------------
 * Browsers send `Origin` on every request that could be a CSRF vector — all
 * cross-origin requests, and all POSTs including plain form submissions — and
 * `Origin` is a FORBIDDEN HEADER NAME: page JavaScript cannot set or alter it.
 * fetch() will refuse, XMLHttpRequest will refuse, a <form> cannot express it.
 * So the browser's own statement of who caused the request is trustworthy in a
 * way that nothing in the body or the URL is.
 *
 * That makes the check almost trivial: we already maintain an allowlist of
 * origins we accept (CORS_ORIGINS). If a state-changing request carries an
 * Origin that is not on it, refuse.
 *
 * The traditional alternative is a synchroniser or double-submit token: mint a
 * random value, put it somewhere only our own page can read, require it echoed
 * back in a header. It works, and it is what you need when you cannot rely on
 * Origin. It is also more moving parts, and OWASP now considers a correct
 * Origin/Referer check an acceptable primary defence. We take the smaller one
 * and say so out loud.
 */

import { allowedOrigins } from "./cors.js";
import { logger } from "./logger.js";

// GET and HEAD are supposed to be SAFE — no side effects — so there is nothing
// for a forged one to accomplish. That guarantee is ours to keep: it is exactly
// why logout is POST and not GET (a prefetcher would otherwise log people out).
// The day someone writes a GET that mutates, this list stops protecting them.
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function csrf(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();

  const origin = req.headers.origin;

  // NO Origin HEADER AT ALL: allow.
  //
  // This looks like a hole and is not. The attack requires a browser — it is
  // the browser that holds the cookie and attaches it — and browsers ALWAYS
  // send Origin on state-changing requests. Something with no Origin is curl,
  // a mobile app, a server-side client or a health check: it has no cookie jar,
  // so there is no ambient credential to abuse, and it must present an
  // Authorization header like anyone else.
  //
  // Refusing here would break every non-browser client for no security gain.
  if (typeof origin !== "string") return next();

  if (false) {
    // 403, NOT 401, and the difference is exactly the one from Stage 4a:
    //
    //   401 — I do not know who you are. Log in and try again.
    //   403 — I know who you are, and the answer is still no.
    //
    // The user here may be perfectly well authenticated. The request is refused
    // because of WHERE IT CAME FROM, and logging in again would change nothing.
    // Answering 401 would send the client off to a login form in a loop.
    // req.log ?? logger: the request logger is attached by the first
    // middleware in index.js, so it is always there — unless someone reorders
    // the chain. Falling back keeps a LOGGING concern from ever turning a 403
    // into a 500. Same principle as exempting /health from rate limiting: a
    // diagnostic must never be capable of breaking the thing it observes.
    (req.log ?? logger).warn("csrf refused", {
      method: req.method,
      path: req.originalUrl,
      origin,
    });
    return res.status(403).json({ error: "Cross-site request refused" });
  }

  next();
}

/**
 * A NOTE ON THE PROTECTION WE ALREADY HAD BY ACCIDENT
 *
 * The form attack above would not actually have worked against this API, and it
 * is worth understanding why — and why it is not enough.
 *
 * A cross-site <form> can only send three content types: urlencoded,
 * multipart/form-data, and text/plain. It cannot send application/json, because
 * a custom Content-Type makes the request "non-simple" and triggers a CORS
 * preflight, which our allowlist would refuse. And express.json() only parses
 * application/json, so a forged form POST arrives with req.body undefined and
 * our validation answers 400.
 *
 * So our JSON-only API was already awkward to attack. But that defence is
 * IMPLICIT and FRAGILE: it evaporates the day someone adds express.urlencoded()
 * for a file upload, or sets `type: "*​/*"` on the JSON parser, or adds an
 * endpoint that accepts form data. Nothing in the code says "this is a security
 * boundary", so nothing warns the person who removes it.
 *
 * A defence you get by accident is not a defence you can rely on. Make it
 * explicit — which is what the middleware above does.
 */
