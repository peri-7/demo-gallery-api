/**
 * Load a pile of fake drawings, so pagination and query plans can be measured
 * on something bigger than eight rows.
 *
 *   node --env-file=.env scripts/seed-bulk.mjs 5000 --not-production
 *
 * Why this is a SCRIPT and not a migration
 * ----------------------------------------
 * Migrations describe the schema every environment must end up with, and they
 * run everywhere, forever, in order. This data is throwaway: it exists so a
 * laptop can watch the planner change its mind. Putting it in migrations/ would
 * mean production runs it too, permanently, with no way to take it back — the
 * files are append-only by design.
 *
 * The rule is about what the file MEANS, not about where the SQL lives:
 * structure is a migration, local test data is a script.
 *
 * The awkward flag is deliberate
 * ------------------------------
 * This writes thousands of rows. There is exactly one thing standing between
 * "seed my dev branch" and "seed production" — which .env file was passed on
 * the command line. That is too thin a barrier for a script that cannot be
 * undone with a single command, so it prints the host it is about to write to
 * and refuses to run without an explicit acknowledgement.
 *
 * Making a destructive tool slightly annoying to invoke is a real engineering
 * control, not a nicety.
 */

import pg from "pg";

const { Client } = pg;

const count = Number(process.argv[2] ?? 5000);
const acknowledged = process.argv.includes("--not-production");

if (!Number.isInteger(count) || count < 1 || count > 200_000) {
  console.error("usage: seed-bulk.mjs <count 1..200000> --not-production");
  process.exit(1);
}

const url = new URL(process.env.DATABASE_URL);
console.log(`target host : ${url.host}`);
console.log(`rows to add : ${count}`);

if (!acknowledged) {
  console.error("\nRefusing to run. Re-run with --not-production if that host is a dev branch.");
  process.exit(1);
}

const client = new Client({ connectionString: process.env.DATABASE_URL });
await client.connect();

const before = await client.query("select count(*)::int as n from drawings");

// generate_series produces rows inside the database, so the 5000 rows are never
// built in JavaScript and never cross the network. One statement, one round
// trip. The alternative — a loop issuing 5000 INSERTs — would take a connection
// hostage for thousands of round trips, each one dominated by latency rather
// than by the work.
const started = Date.now();
await client.query(
  `insert into drawings (title, artist, year, rating, created_at)
   select
     'Study no. ' || g,
     (array[
       'Leonardo da Vinci','Albrecht Durer','Katsushika Hokusai','Pablo Picasso',
       'Kathe Kollwitz','James McNeill Whistler','Egon Schiele','Mary Cassatt',
       'Hokusai Katsushika','Rembrandt van Rijn','Georgia O''Keeffe','Anonymous'
     ])[1 + (g % 12)],
     1500 + (g % 500),
     -- Every 7th drawing is unrated. Nulls in the sort column are not an edge
     -- case to be avoided here: they are the thing that makes pagination hard,
     -- so the test data has to contain them.
     case when g % 7 = 0 then null else round((random() * 5)::numeric, 1) end,
     now() - (g || ' minutes')::interval
   from generate_series(1, $1) g`,
  [count]
);
const elapsed = Date.now() - started;

const after = await client.query("select count(*)::int as n from drawings");

console.log(`\nbefore : ${before.rows[0].n}`);
console.log(`after  : ${after.rows[0].n}`);
console.log(`took   : ${elapsed}ms`);

await client.end();
