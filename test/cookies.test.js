/**
 * Cookie parsing and serialisation.
 *
 * The parsing tests are mostly about REFUSING to guess. The serialisation
 * tests pin down a string whose every attribute is load-bearing — and where a
 * "tidy-up" that drops one is invisible until someone's session is stolen.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  SESSION_COOKIE,
  parseCookies,
  serializeCookie,
  clearSessionCookie,
} from "../src/cookies.js";

const asReq = (cookie) => ({ headers: cookie === undefined ? {} : { cookie } });

describe("parseCookies", () => {
  test("parses a normal header", () => {
    assert.deepEqual(parseCookies(asReq("a=1; b=2")), { a: "1", b: "2" });
  });

  test("returns {} when there is no cookie header", () => {
    assert.deepEqual(parseCookies(asReq(undefined)), {});
  });

  test("decodes percent-encoded values", () => {
    assert.deepEqual(parseCookies(asReq("x=a%20b")), { x: "a b" });
  });

  test("FIRST occurrence wins on a duplicate name", () => {
    // The security-relevant one. A browser will not normally send two cookies
    // with the same name, but an attacker who can write a cookie on a sibling
    // host CAN cause a duplicate — "cookie tossing". Silently taking the last
    // one is how that becomes session fixation. Either rule can be defended;
    // having no rule cannot, so the rule is pinned here.
    assert.deepEqual(parseCookies(asReq("session=ours; session=theirs")), {
      session: "ours",
    });
  });

  test("skips a malformed escape instead of throwing", () => {
    // decodeURIComponent throws on "%zz". A parser that throws turns a
    // malformed cookie — which anyone can send — into a 500.
    assert.deepEqual(parseCookies(asReq("good=1; bad=%zz")), { good: "1" });
  });

  test("skips fragments with no '=' and empty names", () => {
    assert.deepEqual(parseCookies(asReq("novalue; =orphan; ok=1")), { ok: "1" });
  });

  test("never throws on hostile input", () => {
    for (const header of ["", ";", "=", ";;;", "a", "a=", "=b", "a=b=c"]) {
      assert.doesNotThrow(() => parseCookies(asReq(header)), `threw on: ${header}`);
    }
  });
});

describe("serializeCookie", () => {
  test("sets every attribute the cross-site deployment requires", () => {
    const value = serializeCookie(SESSION_COOKIE, "tok", { maxAge: 60 });

    // HttpOnly: page JavaScript cannot read it. Removing this is the single
    // change that would hand the session back to any XSS payload.
    assert.match(value, /HttpOnly/);
    // Secure: never sent over plain HTTP.
    assert.match(value, /Secure/);
    // SameSite=None is FORCED. vercel.app and onrender.com are both on the
    // Public Suffix List, so client and API are different SITES; Lax would
    // refuse to attach the cookie to any request our own client makes.
    assert.match(value, /SameSite=None/);
    // Partitioned (CHIPS): ours is a third-party cookie, and this is what may
    // keep it working where third-party cookies are blocked.
    assert.match(value, /Partitioned/);
  });

  test("sets NO Domain attribute", () => {
    // Host-only, deliberately. Domain=onrender.com would share the session
    // with every other app on that host. An absence is hard to notice in review
    // and trivial to assert.
    assert.doesNotMatch(serializeCookie("s", "v", { maxAge: 60 }), /Domain=/i);
  });

  test("percent-encodes the value", () => {
    assert.match(serializeCookie("s", "a b;c"), /s=a%20b%3Bc/);
  });

  test("Max-Age is an integer", () => {
    // A fractional Max-Age is not valid and browsers may ignore the whole
    // attribute, quietly turning a persistent cookie into a session one.
    assert.match(serializeCookie("s", "v", { maxAge: 60.7 }), /Max-Age=60(;|$)/);
  });
});

describe("clearSessionCookie", () => {
  test("clears with Max-Age=0 and attributes matching the original", () => {
    // There is no "delete cookie" in HTTP: you overwrite with an empty value
    // and Max-Age=0, and the browser matches on Path, Domain, SameSite, Secure
    // and Partitioned to decide WHICH cookie you meant. Get one wrong and the
    // browser empties a different cookie and leaves the real one alone — a
    // logout that appears to do nothing.
    const headers = [];
    const res = { append: (name, value) => headers.push([name, value]) };

    clearSessionCookie(res);

    assert.equal(headers.length, 1);
    const [name, value] = headers[0];
    assert.equal(name, "Set-Cookie");
    assert.match(value, /^session=;/);
    assert.match(value, /Max-Age=0/);

    // The attributes must still match what setSessionCookie writes.
    const set = serializeCookie(SESSION_COOKIE, "tok", { maxAge: 60 });
    for (const attr of ["Path=/", "HttpOnly", "Secure", "SameSite=None", "Partitioned"]) {
      assert.ok(value.includes(attr), `clear is missing ${attr}`);
      assert.ok(set.includes(attr), `set is missing ${attr}`);
    }
  });
});
