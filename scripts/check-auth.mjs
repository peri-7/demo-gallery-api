/**
 * Exercise the auth endpoints over real HTTP.
 *
 *   npm run check:auth              (against http://localhost:3000)
 *   API_URL=https://… npm run check:auth
 *
 * Not a test suite — nothing asserts. It prints request/response pairs so the
 * behaviour can be read, in the same spirit as check-api.mjs. The two sections
 * worth reading slowly are the identical responses to different failures, and
 * the timing comparison at the end.
 */

const API = process.env.API_URL ?? "http://localhost:3000";

// Must be one of the server's CORS_ORIGINS, or the CSRF check below refuses it —
// which is the point. Override when running against production:
//   API_URL=https://… CHECK_ORIGIN=https://… npm run check:auth
const allowedOrigin = process.env.CHECK_ORIGIN ?? "http://localhost:5173";

const email = `check-auth-${Date.now()}@example.invalid`;
const password = "a perfectly reasonable password";

async function call(method, path, { body, token, rawAuth, cookie, origin } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  if (rawAuth) headers.Authorization = rawAuth; // send a header verbatim, valid or not
  if (cookie) headers.Cookie = `session=${cookie}`;
  // Origin is a FORBIDDEN HEADER NAME in a browser — page JavaScript cannot set
  // it, which is exactly why the server can trust it. We are not a browser, so
  // we can claim any origin we like. That asymmetry is the whole reason this
  // script can impersonate an attacker and a real client cannot lie.
  if (origin) headers.Origin = origin;

  const started = Date.now();
  const res = await fetch(`${API}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const ms = Date.now() - started;

  const text = await res.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  return { status: res.status, ms, body: parsed, headers: res.headers };
}

/**
 * Pull the session token out of Set-Cookie.
 *
 * Stage 4b: the token no longer comes back in the response body, because a body
 * is readable by page JavaScript and the entire point of HttpOnly is that the
 * credential is not. It arrives in a Set-Cookie header instead.
 *
 * A browser would store this automatically and never show it to anyone. We are
 * not a browser, so we read the header like any other — which is exactly how a
 * mobile app or a server-side client participates in a cookie flow.
 */
function sessionCookie(headers) {
  const all = headers.getSetCookie?.() ?? [headers.get("set-cookie") ?? ""];
  for (const line of all) {
    const m = /^session=([^;]*)/.exec(line.trim());
    if (m && m[1] !== "") return decodeURIComponent(m[1]);
  }
  return null;
}

function show(label, r, extra = "") {
  const summary = r.body === null ? "(no body)" : JSON.stringify(r.body);
  console.log(`  ${label.padEnd(46)} ${String(r.status).padEnd(4)} ${summary}${extra}`);
}

console.log(`API: ${API}\n`);

// --- signup ----------------------------------------------------------------
console.log("signup:");
show("valid", await call("POST", "/api/auth/signup", { body: { email, password } }));
show("same email again", await call("POST", "/api/auth/signup", { body: { email, password } }));
show("bad email", await call("POST", "/api/auth/signup", { body: { email: "nope", password } }));
show("short password", await call("POST", "/api/auth/signup", { body: { email: `x${email}`, password: "short" } }));
show("password is an array", await call("POST", "/api/auth/signup", { body: { email: `y${email}`, password: ["a", "b"] } }));
show("no body at all", await call("POST", "/api/auth/signup", {}));

// --- login failures ---------------------------------------------------------
console.log("\nlogin failures — note the responses are indistinguishable:");
show("wrong password", await call("POST", "/api/auth/login", { body: { email, password: "wrong password here" } }));
show("no such account", await call("POST", "/api/auth/login", { body: { email: "ghost@example.invalid", password } }));

// --- login success ----------------------------------------------------------
console.log("\nlogin:");
const login = await call("POST", "/api/auth/login", { body: { email, password } });
show("correct credentials", login);
const token = sessionCookie(login.headers);
console.log(`  ${"note: no token in the body".padEnd(46)}      Set-Cookie: session=${token?.slice(0, 12)}…`);
console.log(`  ${"".padEnd(46)}      ${login.headers.get("set-cookie")?.replace(/session=[^;]*/, "session=…")}`);

// --- case and whitespace ----------------------------------------------------
const messy = await call("POST", "/api/auth/login", {
  body: { email: `  ${email.toUpperCase()}  `, password },
});
show("same email, UPPERCASE and padded", { ...messy, body: { ok: messy.status === 200 } });

// --- protected endpoints ----------------------------------------------------
console.log("\nGET /api/auth/me:");
const anon = await call("GET", "/api/auth/me");
show("no token", anon, `   WWW-Authenticate: ${anon.headers.get("www-authenticate")}`);
show("garbage token", await call("GET", "/api/auth/me", { token: "not-a-real-token" }));
show("wrong scheme (Basic)", await call("GET", "/api/auth/me", { rawAuth: `Basic ${token}` }));
show("token with no scheme", await call("GET", "/api/auth/me", { rawAuth: token }));
show("lowercase 'bearer'", await call("GET", "/api/auth/me", { rawAuth: `bearer ${token}` }));
show("valid token", await call("GET", "/api/auth/me", { token }));

console.log("\nwrite endpoints — the point of the whole stage:");
show("POST /api/drawings/upload-url  anonymous",
  await call("POST", "/api/drawings/upload-url", { body: { contentType: "image/png" } }));
const signed = await call("POST", "/api/drawings/upload-url", {
  body: { contentType: "image/png" },
  token,
});
show("POST /api/drawings/upload-url  logged in", { ...signed, body: { key: signed.body.key } });
show("POST /api/drawings              anonymous",
  await call("POST", "/api/drawings", { body: { title: "x", artist: "y", year: 1900 } }));

// --- Stage 4b: the cookie transport, and the CSRF defence it needs -----------
//
// The same session, presented three ways. Only the transport differs — the
// sessions table, the sha256 lookup and requireAuth are identical in all three.
console.log("\nsame session, three transports:");
show("Authorization: Bearer <token>", await call("GET", "/api/auth/me", { token }));
show("Cookie: session=<token>", await call("GET", "/api/auth/me", { cookie: token }));
show("both at once (cookie wins)", await call("GET", "/api/auth/me", { cookie: token, token: "garbage" }));

// This is the attack cookies re-open, and it is worth seeing that the session is
// entirely VALID — nothing was stolen or forged. The request is refused purely
// because of where the browser says it came from.
console.log("\nCSRF — a valid cookie is not enough:");
// A signed URL is a write capability for anyone holding it, so print only the
// key — never the signed URL itself. Same reason the check scripts never print
// DATABASE_URL: a short lifetime is not the same thing as not being a secret.
const csrfCase = async (label, opts) => {
  const r = await call("POST", "/api/drawings/upload-url", {
    body: { contentType: "image/png" },
    cookie: token,
    ...opts,
  });
  show(label, { ...r, body: r.body?.key ? { key: r.body.key } : r.body });
};
await csrfCase("POST from our own origin", { origin: allowedOrigin });
await csrfCase("POST from https://evil.example", { origin: "https://evil.example" });
await csrfCase("POST with no Origin (curl, mobile)", {});
show("GET from https://evil.example (safe method)",
  { ...(await call("GET", "/api/drawings?limit=1", { origin: "https://evil.example" })), body: "(allowed — but evil.example cannot READ it: no Allow-Origin came back)" });

console.log("\nreads stay public:");
const list = await call("GET", "/api/drawings?limit=1");
show("GET /api/drawings  anonymous", { ...list, body: { returned: list.body.drawings.length } });

// --- logout -----------------------------------------------------------------
console.log("\nlogout:");
show("logout", await call("POST", "/api/auth/logout", { token }));
show("me, with the same token", await call("GET", "/api/auth/me", { token }));
show("logout again", await call("POST", "/api/auth/logout", { token }));

// --- the timing oracle that is not there ------------------------------------
//
// The interesting measurement. If the "no such user" path skipped the password
// hash, this would show ~2ms against ~35ms and anyone could enumerate accounts
// without guessing a single password. Both paths hash, so both cost the same.
// STAGE 5 CHANGED THIS MEASUREMENT, AND THE FIRST RUN LOOKED LIKE A REGRESSION.
//
// The per-email failed-login limiter refuses after 5 failures, and it refuses
// BEFORE hashing — which is the entire point of where it sits. So attempts 6
// and 7 come back in 2ms with a 429, and dropping those into the sample set
// produced a row reading "165, 204, 213, 164, 799, 2". The 2 is not a fast
// hash. It is no hash at all.
//
// Two things to take from that. First, a 429 is not a login attempt and must
// not be averaged with them — so they are separated out below rather than
// silently skewing a median. Second, and more useful: adding a defence changed
// what an existing check was measuring, and nothing failed. If this script
// asserted instead of printing, that would have been caught automatically.
// It does not, which is exactly the gap CI is about to close.
console.log("\ntiming — can an outsider tell whether an account exists?");
const samples = 6;
const timings = { real: [], ghost: [] };
for (let i = 0; i < samples; i++) {
  const real = await call("POST", "/api/auth/login", { body: { email, password: "wrong password here" } });
  const ghost = await call("POST", "/api/auth/login", { body: { email: "ghost@example.invalid", password } });
  timings.real.push({ ms: real.ms, status: real.status });
  timings.ghost.push({ ms: ghost.ms, status: ghost.status });
}
const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
function report(label, rows) {
  const hashed = rows.filter((r) => r.status !== 429).map((r) => r.ms);
  const refused = rows.length - hashed.length;
  const shown = hashed.length === 0 ? "n/a" : `${median(hashed)}ms`;
  console.log(
    `  ${label} : median ${shown.padEnd(7)} ${hashed.join(", ")}` +
      (refused > 0 ? `   (+${refused} refused 429, excluded)` : "")
  );
}
report("existing account, wrong password", timings.real);
report("no such account                 ", timings.ghost);
if (timings.real.every((r) => r.status === 429)) {
  console.log(`
  ^ EVERY sample was refused, so nothing was measured. This script makes more
    signup+login calls than RATE_LIMIT_AUTH_PER_IP allows, which is the limiter
    working correctly on a caller that looks exactly like a brute-forcer.
    To measure the timing, restart the server with the limits relaxed:

      RATE_LIMIT_AUTH_PER_IP=200 RATE_LIMIT_LOGIN_FAILURES=100 npm run dev

    Note what you must NOT do: relax the limit inside the server for requests
    that look like this script. A limiter with an exemption for "our own tools"
    is a limiter with a documented bypass.`);
}
console.log(`
Both paths run one scrypt hash. The gap should be noise, not signal — if the
second row were consistently faster, the endpoint would be answering "does this
address have an account here?" to anyone who asked, without a single password
guess.

The 429s are excluded above, and note that BOTH rows collect them. That symmetry
matters: a limiter that only counted real accounts would answer the same
question the dummy hash exists to hide, just with a status code instead of a
stopwatch. Raise RATE_LIMIT_LOGIN_FAILURES if you want more hashed samples.
`);
