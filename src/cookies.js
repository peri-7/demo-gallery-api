/**
 * Cookies, by hand. Like cors.js, the `cookie-parser` package does exactly this,
 * and like cors.js the whole mechanism is small enough to be worth seeing once.
 *
 * A COOKIE IS TWO HEADERS AND A RULEBOOK. That is the entire premise:
 *
 *     server -> browser    Set-Cookie: session=aB3x...; HttpOnly; Secure; ...
 *     browser -> server    Cookie: session=aB3x...
 *
 * There is no cookie "system" beyond those two lines plus the attributes that
 * tell the browser WHEN to attach it. Everything else people mean by "cookies"
 * — sessions, tracking, consent banners — is built on top of this.
 *
 * WHAT CHANGES FROM AN Authorization HEADER, AND WHAT DOES NOT
 * -----------------------------------------------------------
 * The token is the same 43-character string. The sessions table is unchanged.
 * The sha256 lookup is unchanged. ALL that changes is who writes the header:
 * our JavaScript did it before, the browser does it now, automatically.
 *
 * That automation is the entire trade. It buys HttpOnly — the token becomes
 * unreadable to page JavaScript, so XSS cannot steal it — and it costs CSRF,
 * because "automatically" means "even when another site caused the request".
 * See csrf.js for the half we have to build back.
 */

/**
 * The cookie's name. Short and boring on purpose: the name travels on every
 * single request, and it tells anyone reading the wire nothing useful.
 */
export const SESSION_COOKIE = "session";

/**
 * Parse a Cookie request header into an object.
 *
 * The wire format is `name=value; name2=value2` — semicolon separated, with no
 * escaping rules of its own, which is why values are URL-encoded by convention
 * rather than by the spec.
 *
 * Never throws. A malformed Cookie header comes from outside, and a stranger
 * sending a garbled header must not be able to produce a 500.
 */
export function parseCookies(req) {
  const header = req.headers.cookie;
  if (typeof header !== "string") return {};

  const out = {};
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    // A cookie with no "=" is not a name/value pair. Skip rather than guess.
    if (eq < 1) continue;

    const name = part.slice(0, eq).trim();
    const raw = part.slice(eq + 1).trim();
    if (name === "") continue;

    // FIRST occurrence wins, deliberately. A browser will not normally send two
    // cookies with the same name, but an attacker who can write a cookie on a
    // sibling host CAN cause a duplicate to be sent — "cookie tossing".
    // Silently taking the last one is how that becomes a session-fixation bug,
    // so pick one rule and be explicit that it is a rule.
    if (Object.hasOwn(out, name)) continue;

    try {
      out[name] = decodeURIComponent(raw);
    } catch {
      // decodeURIComponent throws on malformed escapes like "%zz". The value is
      // then not something we issued, so treat it as absent.
      continue;
    }
  }
  return out;
}

/**
 * Build a Set-Cookie header value.
 *
 * Every attribute here is load-bearing, and three of them are the reason this
 * stage is hard:
 *
 *   HttpOnly    JavaScript cannot read this cookie. document.cookie will not
 *               show it, and fetch cannot see it. THIS IS THE WHOLE POINT of
 *               moving off the Authorization header: an XSS payload that could
 *               previously read our token out of a variable now cannot reach it
 *               at all. Note what it does NOT stop — a script on our page can
 *               still MAKE requests that carry the cookie. HttpOnly prevents
 *               theft of the credential, not abuse of the session.
 *
 *   Secure      Only ever sent over HTTPS. Required whenever SameSite=None, and
 *               correct regardless: a session cookie on a plaintext connection
 *               is readable by anything between the browser and us.
 *               (Browsers treat localhost as a trustworthy origin, so this
 *               still works in local dev over http.)
 *
 *   SameSite    WHEN the browser attaches this cookie on a request that another
 *               site caused. Three values:
 *                 Strict — never on any cross-site request. Safest, and it
 *                          breaks following a link into your own app.
 *                 Lax    — on top-level navigations only (clicking a link),
 *                          not on background requests like fetch or <img>.
 *                          The modern browser default.
 *                 None   — always. Which is what a cross-SITE API requires, and
 *                          is exactly the setting that re-opens CSRF.
 *
 *               We are forced to None: the client is on vercel.app and the API
 *               is on onrender.com — different registrable domains, therefore
 *               different sites, therefore every one of our API calls is
 *               "cross-site" as far as the browser is concerned. Lax would mean
 *               the cookie is never sent by fetch at all and nothing works.
 *
 *   Partitioned Opts into CHIPS (Cookies Having Independent Partitioned State).
 *               Browsers increasingly block third-party cookies outright, and
 *               ours IS a third-party cookie — indistinguishable from a tracker
 *               from the outside. Partitioned says: key this cookie to the
 *               top-level site as well, so it can never be used to follow a
 *               user across sites. That is a promise we can make honestly,
 *               since we only ever want it on our own client. Support is
 *               uneven; Safari may refuse the cookie regardless. That is a real
 *               limitation of this architecture, not a bug in this file.
 *
 *   Path=/      Sent for every path on this host. Path is NOT a security
 *               boundary — any page on the origin can read any path's cookies —
 *               it is only a way to reduce noise.
 *
 *   (no Domain) Omitting Domain makes the cookie HOST-ONLY: it belongs to
 *               exactly this hostname. Setting `Domain=onrender.com` would
 *               share our session cookie with every other app on onrender.com,
 *               which is a spectacular way to hand your users' sessions to
 *               strangers. Omission is the secure choice.
 */
export function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];

  if (options.maxAge !== undefined) {
    // Max-Age is in SECONDS and is relative, so it needs no agreement about
    // clocks between our server and the user's laptop — unlike Expires, which
    // is an absolute date and is wrong for anyone whose clock is off.
    parts.push(`Max-Age=${Math.floor(options.maxAge)}`);
  }

  parts.push(`Path=${options.path ?? "/"}`);
  if (options.httpOnly !== false) parts.push("HttpOnly");
  if (options.secure !== false) parts.push("Secure");
  parts.push(`SameSite=${options.sameSite ?? "None"}`);
  if (options.partitioned !== false) parts.push("Partitioned");

  return parts.join("; ");
}

/**
 * Attach the session cookie to a response.
 *
 * The cookie's lifetime is derived from the session row's expires_at, so the
 * two agree. But be clear about which one is ENFORCEMENT: the browser deleting
 * an expired cookie is a courtesy, and a cookie can be replayed by anything
 * that is not a browser. The row's `expires_at > now()` in the WHERE clause is
 * what actually ends a session — exactly as in Stage 4a. A client-side expiry
 * is a hint; a server-side one is a rule.
 */
export function setSessionCookie(res, token, expiresAt) {
  const maxAge = Math.max(0, (new Date(expiresAt).getTime() - Date.now()) / 1000);
  res.append("Set-Cookie", serializeCookie(SESSION_COOKIE, token, { maxAge }));
}

/**
 * Remove the session cookie.
 *
 * There is no "delete cookie" instruction in HTTP. You overwrite it with an
 * empty value and Max-Age=0, and the browser drops it. The attributes must
 * MATCH the ones it was set with — Path, SameSite, Secure, Partitioned — or the
 * browser treats it as a different cookie, sets THAT one to empty, and leaves
 * the original in place. A logout that appears to do nothing is almost always
 * this.
 *
 * Note this is cosmetic anyway: routes/auth.js deletes the session ROW, which
 * is what actually ends the session. Clearing the cookie only stops the browser
 * sending a string that now names nothing.
 */
export function clearSessionCookie(res) {
  res.append("Set-Cookie", serializeCookie(SESSION_COOKIE, "", { maxAge: 0 }));
}
