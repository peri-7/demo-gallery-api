/**
 * Two demonstrations, both about LIMIT/OFFSET:
 *
 *   1. It gets slower the deeper you page, and EXPLAIN says exactly why.
 *   2. It can return the same row twice, or skip one, with no error at all.
 *
 * Run against a dev branch with a few thousand rows:
 *   node --env-file=.env scripts/pagination-demo.mjs
 *
 * Nothing here asserts anything. It prints, and you read it — like the other
 * scripts in this folder, it is a way of looking at the system, not a test.
 */

import pg from "pg";

const { Client } = pg;
const client = new Client({ connectionString: process.env.DATABASE_URL });
await client.connect();

const rule = (label) => console.log(`\n${"=".repeat(70)}\n${label}\n${"=".repeat(70)}`);

// ---------------------------------------------------------------------------
// 1. The cost of OFFSET
// ---------------------------------------------------------------------------
//
// EXPLAIN ANALYZE actually runs the query and reports what happened, as opposed
// to plain EXPLAIN which only reports what the planner INTENDED. Two numbers
// matter below:
//
//   "rows removed" / the difference between rows read and rows returned
//   "actual time"
//
// OFFSET does not skip ahead. The database has no way to jump to the 5000th row
// of a sorted result without producing the first 4999 and throwing them away.

rule("1. EXPLAIN ANALYZE — LIMIT 20 at increasing offsets");

for (const offset of [0, 1000, 5000]) {
  const { rows } = await client.query(
    `explain (analyze, buffers, costs off)
     select id, title, year from drawings
     order by year desc, id desc
     limit 20 offset ${offset}`
  );
  console.log(`\n--- offset ${offset} ---`);
  for (const r of rows) console.log("  " + r["QUERY PLAN"]);
}

// The keyset alternative: instead of counting rows to skip, name the last row
// you saw and ask for what comes after it. The database seeks straight into the
// index. Cost does not grow with page number.

rule("2. EXPLAIN ANALYZE — the keyset equivalent, at the SAME depths");

// Anchored at the same positions as the OFFSET queries above, so the two are
// actually comparable. Anchoring at the end of the table would flatter keyset
// for the wrong reason: there would be almost nothing left to return.
for (const depth of [1000, 5000]) {
  const { rows: anchor } = await client.query(
    `select year, id from drawings order by year desc, id desc limit 1 offset ${depth - 1}`
  );

  const { rows: plan } = await client.query(
    `explain (analyze, buffers, costs off)
     select id, title, year from drawings
     where (year, id) < ($1, $2)
     order by year desc, id desc
     limit 20`,
    [anchor[0].year, anchor[0].id]
  );
  console.log(`\n--- row ${depth} onwards (year=${anchor[0].year}) ---`);
  for (const r of plan) console.log("  " + r["QUERY PLAN"]);
}

// ---------------------------------------------------------------------------
// 3. The correctness bug
// ---------------------------------------------------------------------------
//
// A user reads page 1. Before they click "next", somebody inserts a drawing
// that sorts above what they are looking at. Every row shifts down by one
// position, so OFFSET 5 now lands one row earlier than it did a moment ago.
//
// Nothing errors. The user simply sees a row twice and never learns that they
// missed nothing -- or, with a DELETE instead of an INSERT, misses a row and
// never learns that either.

rule("3. LIMIT/OFFSET with a concurrent insert");

const page = (offset) =>
  client.query(
    `select id, title, year from drawings
     order by year desc, id desc
     limit 5 offset $1`,
    [offset]
  );

const p1 = await page(0);
console.log("\npage 1 (offset 0):");
for (const r of p1.rows) console.log(`   ${r.year}  ${r.title}`);

// Sorts above everything: the seeded years top out below 2000.
const inserted = await client.query(
  `insert into drawings (title, artist, year)
   values ('Brand new drawing', 'Someone', 2020) returning id`
);
console.log("\n  >>> someone else inserts a drawing from 2020 <<<");

const p2 = await page(5);
console.log("\npage 2 (offset 5):");
for (const r of p2.rows) console.log(`   ${r.year}  ${r.title}`);

const lastOfPage1 = p1.rows.at(-1);
const duplicated = p2.rows.some((r) => r.id === lastOfPage1.id);
console.log(
  `\n  last row of page 1 : ${lastOfPage1.title}` +
    `\n  appears again on page 2? ${duplicated ? "YES  <-- the bug" : "no"}`
);

// Now the same scenario with a cursor. The client says "after this row",
// not "skip five rows", so an insert elsewhere in the table is irrelevant.
rule("4. The same scenario, keyset");

const k1 = await client.query(
  `select id, title, year from drawings order by year desc, id desc limit 5`
);
console.log("\npage 1:");
for (const r of k1.rows) console.log(`   ${r.year}  ${r.title}`);

const inserted2 = await client.query(
  `insert into drawings (title, artist, year)
   values ('Another new drawing', 'Someone', 2021) returning id`
);
console.log("\n  >>> another insert above the page <<<");

const cur = k1.rows.at(-1);
const k2 = await client.query(
  `select id, title, year from drawings
   where (year, id) < ($1, $2)
   order by year desc, id desc limit 5`,
  [cur.year, cur.id]
);
console.log("\npage 2 (after the last row of page 1):");
for (const r of k2.rows) console.log(`   ${r.year}  ${r.title}`);
console.log(
  `\n  duplicated? ${k2.rows.some((r) => r.id === cur.id) ? "YES" : "no  <-- correct"}`
);

// Put the table back the way we found it.
await client.query(`delete from drawings where id = any($1)`, [
  [inserted.rows[0].id, inserted2.rows[0].id],
]);
console.log("\n(cleaned up the two inserted rows)");

await client.end();
