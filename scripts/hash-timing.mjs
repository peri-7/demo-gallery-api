/**
 * Make the slowness visible.
 *
 *   node scripts/hash-timing.mjs
 *
 * "Password hashing is deliberately slow" is a sentence that is easy to nod at
 * and hard to feel. This prints the actual curve on THIS machine, plus what it
 * means for an attacker who has stolen the users table.
 *
 * Not a test — nothing asserts. It is an instrument.
 */

import { randomBytes, scrypt, createHash } from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt);
const salt = randomBytes(16);
const password = "correct horse battery staple";

async function time(fn, runs = 5) {
  await fn(); // one warm-up: the first call pays for lazily-allocated buffers
  const started = process.hrtime.bigint();
  for (let i = 0; i < runs; i++) await fn();
  return Number(process.hrtime.bigint() - started) / 1e6 / runs;
}

console.log("scrypt cost curve  (r=8, p=1)\n");
console.log("       N     memory      ms/hash    hashes/sec");
console.log("--------------------------------------------------");

let chosen = null;

for (const N of [1024, 4096, 16384, 65536]) {
  const mib = (128 * N * 8) / 1024 / 1024;
  const ms = await time(() =>
    scryptAsync(password, salt, 64, { N, r: 8, p: 1, maxmem: 256 * 1024 * 1024 })
  );
  const perSec = 1000 / ms;
  const mark = N === 16384 ? "  <-- ours" : "";
  console.log(
    `${String(N).padStart(8)}  ${(mib + " MiB").padStart(8)}  ${ms.toFixed(1).padStart(9)}  ${perSec.toFixed(0).padStart(12)}${mark}`
  );
  if (N === 16384) chosen = { ms, perSec };
}

// The comparison that makes the point. sha256 is a perfectly good hash — it is
// one-way and collision-resistant. It is a catastrophic PASSWORD hash for
// exactly one reason: it is fast, and every property an attacker wants is
// "cheap to try again".
const shaMs = await time(() => {
  createHash("sha256").update(password).digest();
  return Promise.resolve();
}, 10000);

console.log("\nFor contrast:");
console.log(`  sha256          ${shaMs.toFixed(5)} ms/hash   ${(1000 / shaMs).toFixed(0)} hashes/sec`);
console.log(`  ratio           scrypt is ~${Math.round(chosen.ms / shaMs)}x slower\n`);

// What that ratio buys, in the only terms that matter: how long a stolen
// database resists an offline guessing attack.
//
// The attacker is not typing into your login form — there is no rate limit, no
// network, no logging. They have the hashes and their own hardware, and they
// try candidates as fast as silicon allows.
const dictionary = 14_000_000; // a routine leaked-password wordlist

console.log("If this table were stolen, one attacker machine at this speed:");
console.log(`  14M-word list vs sha256 : ${humanise(dictionary / (1000 / shaMs))}`);
console.log(`  14M-word list vs scrypt : ${humanise(dictionary / chosen.perSec)}`);
console.log(`
Read it as a per-password cost, not a total: real attackers rent hundreds of
machines. The point is not that scrypt is unbreakable — a password in that
wordlist still falls eventually. The point is that the SAME wordlist costs
seconds against a fast hash and months against a slow one, and that difference
is the entire reason a stolen table is not automatically a stolen account.

Note also what the salt does here that slowness cannot: without it, that
14M-word list is hashed ONCE and checked against every user at the same time.
With it, the whole run above must be repeated separately for every single row.
`);

function humanise(seconds) {
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} seconds`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} minutes`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hours`;
  if (seconds < 86400 * 365) return `${(seconds / 86400).toFixed(1)} days`;
  return `${(seconds / 86400 / 365).toFixed(1)} years`;
}
