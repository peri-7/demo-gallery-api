/**
 * A runnable check of src/password.js.
 *
 *   node scripts/check-password.mjs
 *
 * Not a test suite — nothing asserts, nothing exits non-zero. It prints what
 * happened so the behaviour can be read directly, in the same spirit as
 * check-storage.mjs and check-api.mjs. Real tests arrive in Stage 5 with CI.
 */

import { hashPassword, verifyPassword, needsRehash } from "../src/password.js";

const password = "correct horse battery staple";

const a = await hashPassword(password);
const b = await hashPassword(password);

console.log("stored record:");
console.log(`  ${a}\n`);

console.log("same password hashed twice produces different records:");
console.log(`  first  ...${a.slice(-24)}`);
console.log(`  second ...${b.slice(-24)}`);
console.log(`  equal? ${a === b}   <- must be false; that is the salt working\n`);

console.log("verification:");
console.log(`  correct password          -> ${await verifyPassword(password, a)}`);
console.log(`  wrong password            -> ${await verifyPassword("Correct horse battery staple", a)}`);
console.log(`  correct password vs OTHER record -> ${await verifyPassword(password, b)}   <- true: both are valid records for it`);
console.log(`  empty string              -> ${await verifyPassword("", a)}`);
console.log(`  non-string                -> ${await verifyPassword(null, a)}\n`);

console.log("cost upgrades:");
console.log(`  current record needs rehash?  ${needsRehash(a)}`);
const legacy = a.replace(/N=\d+/, "N=1024");
console.log(`  record made at N=1024?        ${needsRehash(legacy)}   <- login would re-hash it\n`);

console.log("malformed stored records throw (they are OUR data, not user input):");
for (const bad of ["", "not-a-hash", "bcrypt$N=1$a$b", "scrypt$N=x,r=8,p=1$a$b"]) {
  try {
    await verifyPassword(password, bad);
    console.log(`  ${JSON.stringify(bad).padEnd(26)} -> no error (unexpected)`);
  } catch (err) {
    console.log(`  ${JSON.stringify(bad).padEnd(26)} -> ${err.message}`);
  }
}

console.log("\nrejected at hash time:");
for (const bad of ["short", "x".repeat(500)]) {
  try {
    await hashPassword(bad);
    console.log(`  length ${String(bad.length).padStart(3)} -> accepted`);
  } catch (err) {
    console.log(`  length ${String(bad.length).padStart(3)} -> ${err.message}`);
  }
}
