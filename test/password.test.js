/**
 * Password hashing.
 *
 * These are the slowest tests in the suite by a wide margin, and that is the
 * feature working: each hash is ~35ms locally by design. If this file ever
 * becomes fast, someone has lowered the cost parameters.
 *
 * Note what is NOT asserted: the exact duration. A timing assertion is flaky on
 * shared CI hardware, and CLAUDE.md already records the rule that the cost is
 * tuned against DEPLOY hardware (~300ms on Render), not a laptop. What is
 * asserted is the shape — that the parameters travel in the record, so
 * needsRehash can read them back.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH,
  hashPassword,
  verifyPassword,
  needsRehash,
} from "../src/password.js";

const GOOD = "a perfectly reasonable password";

describe("hashPassword", () => {
  test("round-trips", async () => {
    assert.equal(await verifyPassword(GOOD, await hashPassword(GOOD)), true);
  });

  test("rejects the wrong password", async () => {
    assert.equal(await verifyPassword("something else entirely", await hashPassword(GOOD)), false);
  });

  test("the same password twice produces DIFFERENT records", async () => {
    // The salt, doing its job. Without it, identical passwords produce
    // identical hashes — so cracking one cracks every account that shares it,
    // and a precomputed table cracks all of them at once.
    assert.notEqual(await hashPassword(GOOD), await hashPassword(GOOD));
  });

  test("the record is self-describing", async () => {
    // scrypt$N=…,r=…,p=…$salt$hash — the parameters travel WITH the hash, which
    // is what makes raising the cost later possible at all. A record that only
    // stored the digest could never be upgraded, because nothing would know
    // what it was made with.
    assert.match(await hashPassword(GOOD), /^scrypt\$N=\d+,r=\d+,p=\d+\$[^$]+\$[^$]+$/);
  });

  test("stores no plaintext", async () => {
    assert.ok(!(await hashPassword(GOOD)).includes(GOOD));
  });

  test("normalises unicode, so the same typed password verifies", async () => {
    // "é" can be one code point or two. Without NFC, a password typed on one
    // keyboard would not verify when typed on another — a bug that looks like
    // "my password stopped working" and is unreproducible by anyone else.
    const composed = "café-password-1";
    const decomposed = composed.normalize("NFD");
    assert.notEqual(composed, decomposed);
    assert.equal(await verifyPassword(decomposed, await hashPassword(composed)), true);
  });
});

describe("input limits", () => {
  test("refuses to hash a password below the minimum", async () => {
    await assert.rejects(() => hashPassword("x".repeat(MIN_PASSWORD_LENGTH - 1)), RangeError);
  });

  test("refuses to hash a password above the maximum", async () => {
    // A hash's cost includes its input, so an unbounded password is a free
    // denial-of-service: submit a megabyte and make the server do the work.
    await assert.rejects(() => hashPassword("x".repeat(MAX_PASSWORD_LENGTH + 1)), RangeError);
  });

  test("verify returns false for an over-long candidate, rather than throwing", async () => {
    // The asymmetry is deliberate. A bad password arrives from OUTSIDE and is
    // an expected event; throwing would turn a probe into a 500. Note it must
    // not spend a hash on it either — that would be the DoS it is guarding.
    const stored = await hashPassword(GOOD);
    assert.equal(await verifyPassword("x".repeat(MAX_PASSWORD_LENGTH + 1), stored), false);
  });

  test("verify returns false for non-strings and empty input", async () => {
    const stored = await hashPassword(GOOD);
    for (const bad of ["", null, undefined, 42, {}, []]) {
      assert.equal(await verifyPassword(bad, stored), false, `accepted: ${JSON.stringify(bad)}`);
    }
  });
});

describe("malformed stored records THROW", () => {
  // The other half of the asymmetry, and the reason it matters: a bad record
  // comes from OUR OWN DATABASE and is impossible unless something is broken —
  // a partial write, a bad migration, a column holding the wrong thing.
  // Silently returning false would turn data corruption into "that one user's
  // password stopped working", which is a bug report nobody can act on.
  const cases = {
    "not a string": 12345,
    "too few fields": "scrypt$N=16384,r=8,p=1$onlythree",
    "unknown scheme": "bcrypt$N=16384,r=8,p=1$c2FsdA==$aGFzaA==",
    "non-numeric N": "scrypt$N=notanumber,r=8,p=1$c2FsdA==$aGFzaA==",
    "trailing junk in N": "scrypt$N=16384junk,r=8,p=1$c2FsdA==$aGFzaA==",
  };

  for (const [name, stored] of Object.entries(cases)) {
    test(name, async () => {
      await assert.rejects(() => verifyPassword(GOOD, stored));
    });
  }
});

describe("needsRehash", () => {
  test("false for a record made at today's parameters", async () => {
    assert.equal(needsRehash(await hashPassword(GOOD)), false);
  });

  test("true for a record made at weaker parameters", () => {
    // The only moment a password can be re-hashed is a SUCCESSFUL login — the
    // one moment the plaintext is legitimately in memory. Failing to do this is
    // why applications end up with rows still protected by parameters chosen a
    // decade ago.
    assert.equal(needsRehash("scrypt$N=1024,r=8,p=1$c2FsdA==$aGFzaA=="), true);
  });
});
