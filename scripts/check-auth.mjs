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

const email = `check-auth-${Date.now()}@example.invalid`;
const password = "a perfectly reasonable password";

async function call(method, path, { body, token, rawAuth } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  if (rawAuth) headers.Authorization = rawAuth; // send a header verbatim, valid or not

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
show("correct credentials", { ...login, body: { ...login.body, token: `${login.body.token.slice(0, 12)}…` } });
const token = login.body.token;

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
console.log("\ntiming — can an outsider tell whether an account exists?");
const samples = 6;
const timings = { real: [], ghost: [] };
for (let i = 0; i < samples; i++) {
  timings.real.push((await call("POST", "/api/auth/login", { body: { email, password: "wrong password here" } })).ms);
  timings.ghost.push((await call("POST", "/api/auth/login", { body: { email: "ghost@example.invalid", password } })).ms);
}
const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
console.log(`  existing account, wrong password : median ${median(timings.real)}ms   ${timings.real.join(", ")}`);
console.log(`  no such account                  : median ${median(timings.ghost)}ms   ${timings.ghost.join(", ")}`);
console.log(`
Both paths run one scrypt hash. The gap should be noise, not signal — if the
second row were consistently faster, the endpoint would be answering "does this
address have an account here?" to anyone who asked, without a single password
guess.
`);
