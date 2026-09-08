/**
 * Redaction tests.
 *
 * THIS FILE EXISTS BECAUSE OF A REAL BUG, AND ONE TEST HERE IS THAT BUG.
 *
 * The first version of logger.js redacted err.message and passed err.stack
 * through untouched. A stack trace BEGINS WITH THE MESSAGE, so the output was:
 *
 *   message: "[redacted:connection-string]"
 *   stack:   "Error: could not connect to postgresql://user:hunter2@…"
 *
 * It was caught by running scripts/check-logging.mjs and reading the output.
 * That worked, and it is not a system: it depended on someone being careful on
 * a particular afternoon. "a secret in a stack trace is redacted" as a test
 * means the next person to touch that file is TOLD, immediately, in CI.
 *
 * Which is the difference this whole stage is about. An instrument displays a
 * number and hopes you look. A test fails.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { _redact } from "../src/logger.js";

describe("redaction by key name", () => {
  test("redacts the credential headers that ride on every request", () => {
    const out = _redact({
      headers: {
        cookie: "session=REAL-TOKEN",
        authorization: "Bearer REAL-TOKEN",
        "content-type": "application/json",
      },
    });

    assert.equal(out.headers.cookie, "[redacted]");
    assert.equal(out.headers.authorization, "[redacted]");
    // Not everything is a secret. A redactor that eats the whole line is one
    // people switch off, and then nothing is redacted.
    assert.equal(out.headers["content-type"], "application/json");
  });

  test("is case-insensitive, because header names arrive in any case", () => {
    const out = _redact({ Cookie: "session=x", AUTHORIZATION: "Bearer y" });
    assert.equal(out.Cookie, "[redacted]");
    assert.equal(out.AUTHORIZATION, "[redacted]");
  });

  test("applies at every depth, not just the top level", () => {
    const out = _redact({ session: { user: { email: "a@b.c" }, token: "SECRET" } });
    assert.equal(out.session.token, "[redacted]");
    // The surrounding structure survives — redaction should remove the secret,
    // not the context that makes the line useful.
    assert.equal(out.session.user.email, "a@b.c");
  });

  test("redacts inside arrays", () => {
    const out = _redact({ items: [{ password: "hunter2" }] });
    assert.equal(out.items[0].password, "[redacted]");
  });
});

describe("redaction by value", () => {
  test("removes credentials from a connection string, keeping the host", () => {
    const out = _redact({ note: "connect to postgresql://user:hunter2@ep-x.neon.tech/db" });

    assert.ok(!out.note.includes("hunter2"), "the password must not survive");
    // And the rest MUST survive. The first fix replaced the whole string with a
    // placeholder, which was safe and useless: an error with no host and no
    // path tells you nothing about where it came from. Redaction that destroys
    // diagnosability gets switched off, and then it protects nothing.
    assert.ok(out.note.includes("ep-x.neon.tech"), "the host must remain");
    assert.ok(out.note.includes("[redacted]"), "the removal must be visible");
  });

  test("works for any scheme, not just postgres", () => {
    const out = _redact({ a: "redis://u:p@h:6379", b: "mongodb://u:p@h/db" });
    assert.ok(!out.a.includes(":p@"));
    assert.ok(!out.b.includes(":p@"));
  });

  test("leaves an ordinary URL with a port alone", () => {
    // No credentials, so nothing to remove. Guards against a pattern greedy
    // enough to mangle every URL it sees.
    const out = _redact({ url: "https://demo-gallery-api.onrender.com:443/api/hello" });
    assert.equal(out.url, "https://demo-gallery-api.onrender.com:443/api/hello");
  });
});

describe("errors", () => {
  // THE REGRESSION TEST. This is the bug, written down.
  test("a secret in a stack trace is redacted, not just in the message", () => {
    const err = new Error("could not connect to postgresql://user:hunter2@ep-x.neon.tech/db");
    const out = _redact({ err });

    assert.ok(!out.err.message.includes("hunter2"), "message must be clean");
    assert.ok(!out.err.stack.includes("hunter2"), "STACK must be clean — it starts with the message");
  });

  test("also redacts a chained cause", () => {
    // Node 16.9+ chains errors, and a cause is another Error carrying its own
    // message and stack — the same leak, one level down.
    const err = new Error("startup failed", {
      cause: new Error("postgresql://user:hunter2@ep-x.neon.tech/db refused"),
    });
    const out = _redact({ err });
    assert.ok(!JSON.stringify(out).includes("hunter2"));
  });

  test("serialises an Error at all", () => {
    // Guards the thing that looks like it works and does not:
    // JSON.stringify(new Error("boom")) is "{}", because message, name and
    // stack are non-enumerable. Without explicit handling, every logged error
    // is an empty object and the log says nothing.
    const out = _redact({ err: new Error("boom") });
    assert.equal(out.err.message, "boom");
    assert.equal(out.err.name, "Error");
    assert.ok(typeof out.err.stack === "string" && out.err.stack.length > 0);
  });
});

describe("robustness", () => {
  test("survives a circular structure", () => {
    // A pg error reaches the connection, which reaches the socket, which
    // reaches back. Unbounded, one log call serialises the universe or throws —
    // and a logger that throws takes the request with it.
    const a = { name: "a" };
    a.self = a;
    assert.doesNotThrow(() => _redact({ a }));
  });

  test("passes primitives and null through untouched", () => {
    const out = _redact({ n: 42, b: true, z: null, u: undefined });
    assert.equal(out.n, 42);
    assert.equal(out.b, true);
    assert.equal(out.z, null);
    assert.equal(out.u, undefined);
  });
});
