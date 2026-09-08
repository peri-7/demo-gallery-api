/**
 * Watch the rate limiter work. A demonstration, not a test — nothing asserts.
 *
 *   npm run check:ratelimit                    (local, needs the dev server up)
 *   API_URL=https://... npm run check:ratelimit
 *
 * WHAT TO WATCH FOR, IN ORDER
 * ---------------------------
 * 1. RateLimit-Remaining counting down on ordinary requests, before anything is
 *    refused. A caller should be able to see the wall coming.
 * 2. The 429 arriving with a Retry-After that is TRUE — the sliding window log
 *    knows exactly when the oldest hit falls out. A fixed-window counter would
 *    have to guess.
 * 3. Failed logins for an address that DOES NOT EXIST getting limited too. That
 *    is the anti-enumeration property: if only real accounts were counted, the
 *    limiter would answer the question the dummy hash exists to hide.
 * 4. The two limiters being independent — burning the per-email budget for one
 *    address leaves another address unaffected.
 */

const API_URL = (process.env.API_URL ?? "http://localhost:3000").replace(/\/$/, "");

// Random so repeated runs do not collide with each other's budgets, and so
// nothing here can ever match a real account.
const suffix = Math.random().toString(36).slice(2, 10);
const GHOST_EMAIL = `check-ratelimit-${suffix}@example.invalid`;
const OTHER_EMAIL = `check-ratelimit-${suffix}-other@example.invalid`;

async function call(path, { method = "GET", body } = {}) {
  const res = await fetch(`${API_URL}${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let parsed = null;
  try {
    parsed = await res.json();
  } catch {
    /* a proxy or platform error need not be JSON */
  }
  return {
    status: res.status,
    body: parsed,
    limit: res.headers.get("ratelimit-limit"),
    remaining: res.headers.get("ratelimit-remaining"),
    reset: res.headers.get("ratelimit-reset"),
    retryAfter: res.headers.get("retry-after"),
  };
}

function line(label, r) {
  const headers =
    r.limit === null
      ? "(no RateLimit headers)"
      : `limit=${r.limit} remaining=${r.remaining} reset=${r.reset}s` +
        (r.retryAfter ? ` retry-after=${r.retryAfter}s` : "");
  console.log(`  ${label.padEnd(34)} ${String(r.status).padEnd(4)} ${headers}`);
}

console.log(`\nRate limit check against ${API_URL}\n`);

// ---------------------------------------------------------------------------
console.log("1. The global limiter counts down on ordinary reads");
console.log("   (GET /api/drawings — cheap, so the budget is generous)\n");

for (let i = 1; i <= 3; i++) {
  line(`GET /api/drawings #${i}`, await call("/api/drawings?limit=1"));
}

// ---------------------------------------------------------------------------
console.log("\n2. /health is exempt — a 429 here would tell Render we are dead\n");

line("GET /health", await call("/health"));

// ---------------------------------------------------------------------------
console.log("\n3. Failed logins against an address that does not exist");
console.log("   The per-email counter must limit these too, or 429-vs-401");
console.log("   becomes a perfect account-existence oracle.\n");

for (let i = 1; i <= 7; i++) {
  const r = await call("/api/auth/login", {
    method: "POST",
    body: { email: GHOST_EMAIL, password: "not-the-password-either" },
  });
  const note = r.status === 429 ? "  <-- refused BEFORE the 300ms hash" : "";
  line(`login attempt #${i}${note}`, r);
}

// ---------------------------------------------------------------------------
console.log("\n4. A different address is unaffected — the budget is per-email\n");

line(
  "login, different address",
  await call("/api/auth/login", {
    method: "POST",
    body: { email: OTHER_EMAIL, password: "not-the-password-either" },
  })
);

console.log(`
Notes
-----
- The RateLimit-* headers on a per-email 429 describe the PER-IP limiter, which
  is the one the middleware applied. So you will see limit=20 next to a refusal
  that came from the limit of 5. They are two different budgets and only one of
  them is published — deliberately, since a live countdown of another user's
  failure budget would leak that someone else is being attacked.
- Watch the per-IP remaining keep falling during the 429s in step 3. A request
  refused by the email limiter still cost a request, and still counts.
- If step 4 also returned 429, the per-IP limiter caught you first: seven logins
  plus this one is eight of RATE_LIMIT_AUTH_PER_IP. That is the two limiters
  layering correctly, not a bug — raise the env var locally to see them apart.
- Run this against production once and read the server log line for xff. If it
  has more entries than TRUST_PROXY_HOPS accounts for, every caller is sharing
  one bucket and the limit above is a global limit, not a per-client one.
`);
