/**
 * Password hashing. The only file in this project allowed to see a plaintext
 * password, and it never stores, logs or returns one.
 *
 * WHY scrypt, AND WHY FROM NODE ITSELF
 * ------------------------------------
 * The usual advice is bcrypt or argon2, and both are good. scrypt is chosen
 * here for two reasons:
 *
 *   1. It is in Node's standard library. No native compilation, no build step
 *      on Windows, and no third-party package sitting in the one code path
 *      that touches every password in the system. That last point is not
 *      paranoia — a supply-chain compromise of a hashing library is about the
 *      worst dependency you could have.
 *
 *   2. It is MEMORY-HARD, which is the property that matters in 2026. A GPU
 *      has thousands of cores and very little memory per core, so an algorithm
 *      that merely costs CPU (like sha256 in a loop) parallelises beautifully
 *      for the attacker. scrypt forces each guess to allocate a large block of
 *      memory, which is the resource a GPU cannot multiply.
 *
 * The general point is bigger than the choice: a password hash is slow ON
 * PURPOSE. Everywhere else in this codebase, slow is a bug to be fixed. Here it
 * is the feature, and the tuning question is "how slow can I afford to be?"
 * rather than "how fast can I get?".
 */

import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

// scrypt is callback-based. promisify turns it into the async function the rest
// of the codebase expects. There IS a synchronous scryptSync, and using it
// would be a mistake: it blocks the event loop for the full cost of the hash,
// so ten simultaneous logins would queue behind each other and the eleventh
// request — a plain GET of the gallery — would wait for all of them. The async
// form runs on libuv's threadpool and leaves the loop free.
const scryptAsync = promisify(scrypt);

/**
 * The cost parameters, and what they actually cost.
 *
 *   N — the work factor. Doubling it doubles both time AND memory.
 *   r — block size. Memory used is roughly 128 * N * r bytes.
 *   p — parallelism. Left at 1; raising it multiplies CPU without raising the
 *       memory requirement, which weakens exactly the property we chose scrypt
 *       for.
 *
 * At N=16384, r=8 the memory per hash is 128 * 16384 * 8 = 16 MiB.
 *
 * That number matters twice. Node's default maxmem cap is 32 MiB, so raising N
 * one more step (32768 → 32 MiB) fails with an error rather than being slow —
 * which is why maxmem is passed explicitly below instead of relying on the
 * default. And 16 MiB per concurrent login is real server memory: on Render's
 * free 512 MiB instance, a burst of logins is a resource question, not just a
 * latency one.
 *
 * These are the OWASP-recommended minimums. The target to tune against is
 * roughly 100-250ms on the hardware you actually deploy to — slow enough that
 * offline guessing is punishing, fast enough that a human logging in does not
 * notice. Measure it, do not guess: scripts/hash-timing.mjs prints the curve.
 */
const PARAMS = { N: 16384, r: 8, p: 1 };

const KEY_LENGTH = 64; // bytes of derived output
const SALT_LENGTH = 16; // 128 bits of randomness, per user

/**
 * An upper bound on password length, and it is a security control rather than a
 * user-interface preference.
 *
 * scrypt's cost includes the input, so a caller who POSTs a 10 MB "password"
 * makes the server allocate and hash 10 MB — repeatedly, for free, before any
 * authentication has happened. That is a denial of service delivered through
 * the login form. Anything unbounded that arrives from outside and is expensive
 * to process needs a limit; this is that limit.
 *
 * (bcrypt has a notorious version of this problem in reverse: it silently
 * ignores everything after byte 72, so two different long passwords can be the
 * same password. scrypt does not truncate, which is why we must cap explicitly
 * rather than inherit a cap by accident.)
 */
export const MIN_PASSWORD_LENGTH = 10;
export const MAX_PASSWORD_LENGTH = 200;

/**
 * Hash a password into the self-describing string stored in users.password_hash:
 *
 *     scrypt$N=16384,r=8,p=1$<salt base64>$<hash base64>
 *
 * The parameters travel with the hash so the cost can be raised later without
 * invalidating rows created under the old settings. See migration 005.
 */
export async function hashPassword(plain) {
  assertUsablePassword(plain);

  // randomBytes, never Math.random(). Math.random() is a fast statistical
  // generator with a predictable internal state — fine for shuffling a list,
  // catastrophic for anything an attacker benefits from predicting. randomBytes
  // draws from the operating system's CSPRNG.
  const salt = randomBytes(SALT_LENGTH);

  const derived = await scryptAsync(plain.normalize("NFC"), salt, KEY_LENGTH, {
    ...PARAMS,
    maxmem: 64 * 1024 * 1024,
  });

  return [
    "scrypt",
    `N=${PARAMS.N},r=${PARAMS.r},p=${PARAMS.p}`,
    salt.toString("base64"),
    derived.toString("base64"),
  ].join("$");
}

/**
 * Check a candidate password against a stored hash record.
 *
 * Returns a boolean. It does not throw for a wrong password — that is a normal,
 * expected outcome, not an error.
 */
export async function verifyPassword(plain, stored) {
  // A wrong-shaped candidate is simply wrong. Do not spend a hash on it, and do
  // not throw: a 400-length password submitted to a login form is an attacker
  // probing, not a server fault.
  if (typeof plain !== "string" || plain.length === 0) return false;
  if (plain.length > MAX_PASSWORD_LENGTH) return false;

  const record = parseHash(stored);

  const derived = await scryptAsync(plain.normalize("NFC"), record.salt, record.hash.length, {
    N: record.N,
    r: record.r,
    p: record.p,
    maxmem: 64 * 1024 * 1024,
  });

  // timingSafeEqual, not === .
  //
  // A normal comparison returns as soon as it finds a differing byte, so a
  // guess sharing the first three bytes takes measurably longer to reject than
  // one differing immediately. Over enough samples that difference leaks the
  // correct value one byte at a time — you never have to guess the whole thing
  // at once, which collapses the search from astronomical to trivial.
  //
  // timingSafeEqual always reads every byte. It also THROWS on a length
  // mismatch (the lengths are not themselves secret), so guard first.
  if (derived.length !== record.hash.length) return false;
  return timingSafeEqual(derived, record.hash);
}

/**
 * Does this stored hash use weaker parameters than we now require?
 *
 * The cost has to rise over the years, and the only moment a password can be
 * re-hashed is the one moment the plaintext is legitimately in memory: a
 * SUCCESSFUL login. Hence the pattern in the login route — verify, and if the
 * record is stale, hash again at the current cost and update the row. The user
 * notices nothing.
 */
export function needsRehash(stored) {
  const record = parseHash(stored);
  return record.N < PARAMS.N || record.r < PARAMS.r || record.p < PARAMS.p;
}

function assertUsablePassword(plain) {
  if (typeof plain !== "string") throw new TypeError("password must be a string");
  if (plain.length < MIN_PASSWORD_LENGTH) {
    throw new RangeError(`password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  if (plain.length > MAX_PASSWORD_LENGTH) {
    throw new RangeError(`password must be at most ${MAX_PASSWORD_LENGTH} characters`);
  }
}

/**
 * Parse a stored record back into its parts.
 *
 * This one DOES throw on malformed input, and the asymmetry with
 * verifyPassword() is deliberate. A bad password comes from outside and is
 * expected. A bad hash record comes from our own database and is impossible
 * unless something is broken — a partial write, a bad migration, a column
 * holding the wrong thing. Failing loudly with a 500 is correct: silently
 * returning false would turn data corruption into "that user's password stopped
 * working", which is a bug report nobody can act on.
 */
function parseHash(stored) {
  if (typeof stored !== "string") throw new TypeError("stored hash must be a string");

  const parts = stored.split("$");
  if (parts.length !== 4) throw new Error("malformed password hash: wrong number of fields");

  const [scheme, paramString, saltB64, hashB64] = parts;
  if (scheme !== "scrypt") throw new Error(`unsupported password hash scheme: ${scheme}`);

  const params = {};
  for (const pair of paramString.split(",")) {
    const [key, value] = pair.split("=");
    // Number(), not parseInt(): parseInt("16384junk") is 16384, which would
    // accept a corrupted record. Number("16384junk") is NaN. Same rule as the
    // query-string parsing in routes/drawings.js.
    params[key] = Number(value);
  }

  for (const key of ["N", "r", "p"]) {
    if (!Number.isInteger(params[key]) || params[key] < 1) {
      throw new Error(`malformed password hash: bad ${key}`);
    }
  }

  return {
    N: params.N,
    r: params.r,
    p: params.p,
    salt: Buffer.from(saltB64, "base64"),
    hash: Buffer.from(hashB64, "base64"),
  };
}
