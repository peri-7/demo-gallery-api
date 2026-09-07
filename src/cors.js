// Hand-rolled CORS. The `cors` npm package does exactly this, but the whole
// mechanism is ~40 lines and worth seeing once.
//
// Remember what this is and isn't: these headers are INSTRUCTIONS TO THE
// BROWSER, telling it whether to let page JavaScript read our response. They
// are not access control. curl, Postman and any server-side client ignore them
// entirely and always could. Real protection is authentication and
// authorization inside the handlers.

// Comma-separated allowlist, e.g.
//   CORS_ORIGINS=http://localhost:5173,https://demo-gallery.vercel.app
export const allowedOrigins = (process.env.CORS_ORIGINS ?? "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

export function cors(req, res, next) {
  const origin = req.headers.origin;

  // Tell caches that the response body/headers depend on the Origin header.
  // Without this, a shared cache could serve a response computed for origin A
  // to a request from origin B. Set it even when we reject, and even when
  // there is no Origin header at all.
  res.setHeader("Vary", "Origin");

  // No Origin header => not a cross-origin browser request (curl, a health
  // check, same-origin navigation). Nothing to negotiate.
  if (!origin) return next();

  if (allowedOrigins.includes(origin)) {
    // Echo the exact origin back. Not "*" — a wildcard is incompatible with
    // credentials, and echoing is what lets us support several origins.
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  // If it is NOT allowed we deliberately set no headers and still continue.
  // The browser will reject the response on the page's behalf. We do not send
  // 403: the request itself is not forbidden, and pretending otherwise would
  // hide real errors behind a fake one.

  // Preflight. The browser sends OPTIONS before "non-simple" requests — any
  // method beyond GET/HEAD/POST, or custom headers like Authorization or
  // Content-Type: application/json — to ask permission BEFORE sending the
  // real request. Answer it here and stop; it must never reach a route.
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
    // How long the browser may cache this answer, in seconds. Without it,
    // every mutating request costs two round trips instead of one.
    res.setHeader("Access-Control-Max-Age", "600");
    return res.sendStatus(204);
  }

  next();
}
