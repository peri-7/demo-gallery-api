// The migration runner.
//
// This is the entire mechanism behind Flyway, node-pg-migrate, Knex migrations
// and Drizzle Kit. They add niceties — rollbacks, TypeScript definitions,
// locking, dry runs — but the core is what you see here:
//
//   1. keep a table listing which migration files have already run
//   2. read the migrations directory, sorted by filename
//   3. for each file not in that table, run it and record it, atomically
//
// Run with:  npm run migrate

import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pool } from "./db.js";

// ESM has no __dirname. import.meta.url is this file's URL; converting it to a
// path and taking the directory gives the same thing.
const here = path.dirname(fileURLToPath(import.meta.url));
const migrationsDir = path.join(here, "..", "migrations");

async function main() {
  // pool.connect() borrows ONE specific connection and holds it. This matters:
  // BEGIN and COMMIT are session state, so they must be issued on the same
  // connection. pool.query() may hand out a different connection per call,
  // which would leave a transaction open on one and orphan statements on
  // another. See THEORY.md §10, "the trap".
  const client = await pool.connect();

  try {
    // The bookkeeping table, created by the runner itself. It has to be
    // idempotent because it cannot be a migration — it is what tracks them.
    await client.query(`
      create table if not exists schema_migrations (
        filename    text primary key,
        applied_at  timestamptz not null default now()
      )
    `);

    const { rows } = await client.query("select filename from schema_migrations");
    const applied = new Set(rows.map((r) => r.filename));

    // Sorted lexicographically, which is why files are named 001_, 002_, ...
    // rather than 1_, 2_ — "10" sorts before "2".
    const files = (await readdir(migrationsDir)).filter((f) => f.endsWith(".sql")).sort();

    if (files.length === 0) {
      console.log("No migration files found in", migrationsDir);
      return;
    }

    let ran = 0;

    for (const file of files) {
      if (applied.has(file)) {
        console.log(`  skip   ${file}`);
        continue;
      }

      const sql = await readFile(path.join(migrationsDir, file), "utf8");
      process.stdout.write(`  apply  ${file} ... `);

      // One transaction per migration. In Postgres, DDL is transactional:
      // CREATE TABLE can be rolled back like any other statement. So a
      // migration that fails halfway leaves the database exactly as it was —
      // no half-applied schema to clean up by hand.
      //
      // This is NOT true in MySQL, where DDL causes an implicit commit. It is
      // one of the genuinely nicer things about Postgres, and it is why this
      // runner can be so short.
      await client.query("BEGIN");
      try {
        await client.query(sql);
        await client.query(
          "insert into schema_migrations (filename) values ($1)",
          [file]
        );
        await client.query("COMMIT");
        console.log("ok");
        ran++;
      } catch (err) {
        await client.query("ROLLBACK");
        console.log("FAILED");
        // Stop immediately. Later migrations may assume this one succeeded,
        // so running them would compound the damage.
        throw new Error(`${file}: ${err.message}`, { cause: err });
      }
    }

    console.log(
      ran === 0 ? "Database already up to date." : `Applied ${ran} migration(s).`
    );
  } finally {
    // Give the connection back, then shut the pool down so Node can exit.
    // Without pool.end() the process hangs with an idle socket open.
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error("\nMigration failed:", err.message);
  process.exit(1);
});
