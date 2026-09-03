-- Stage 2: teach the drawings table about the file that goes with the drawing.
--
-- Note what this migration does NOT contain: the image itself. The database
-- stores a *reference* — the object key, plus enough metadata to render a page
-- without fetching the file. The bytes live in object storage. Nothing about
-- the picture is in Postgres.

alter table drawings
  -- The object key inside the bucket, e.g. "drawings/9f3c....jpg". Not a URL:
  -- URLs contain the bucket host, which changes if we ever move providers or
  -- put a CDN in front. Storing the key and building the URL at read time means
  -- a provider migration is a config change, not an UPDATE over every row.
  --
  -- UNIQUE because two rows pointing at the same object means deleting either
  -- one breaks the other. The constraint makes that unrepresentable.
  add column storage_key text unique,

  -- Sent back to the browser so an <img> gets the right type, and checked here
  -- so the database refuses anything that isn't an image even if the API's
  -- validation is bypassed or buggy. The API is not the only possible writer —
  -- a migration, a psql session, or a future service could insert rows too.
  -- Constraints are the only guarantee that survives all of them.
  add column content_type text
    check (content_type in ('image/jpeg', 'image/png', 'image/webp')),

  -- integer, not bigint: 2^31 bytes is 2 GB, far above any limit we'd allow.
  -- The upper bound here (10 MB) must stay in sync with the limit the API
  -- enforces when it signs the URL — see storage.js.
  add column size_bytes integer
    check (size_bytes between 1 and 10485760);

-- A row-level invariant, not a column-level one: these three columns are a
-- single fact ("this drawing has a file") split across three fields. Either all
-- three are present or none are. Anything in between — a key with no
-- content_type, a size with no key — is a bug that would otherwise sit in the
-- table indefinitely.
--
-- num_nonnulls() counts how many of its arguments are NOT NULL. This is exactly
-- the kind of constraint that is impossible to express in application code,
-- because application code only sees the writes it performs itself.
alter table drawings
  add constraint drawings_file_all_or_nothing
  check (num_nonnulls(storage_key, content_type, size_bytes) in (0, 3));

-- Why all three columns are NULLABLE even though every future drawing will have
-- a file:
--
-- The table already contains 8 seeded rows with no file. `add column ... not
-- null` with no default would fail instantly against them, and a default would
-- be a lie — those rows genuinely have no image.
--
-- This is expand/contract in miniature (THEORY.md §10). The permissive version
-- ships first; tightening to NOT NULL is a later migration, possible only once
-- every row satisfies it. You cannot go straight to the strict schema when the
-- data doesn't support it yet, and pretending otherwise is how migrations fail
-- in production but pass on an empty dev database.

-- Partial index: only rows that actually have a file. The gallery's main query
-- will eventually filter to drawings with images, and indexing the NULLs would
-- be pure waste — they can never match.
create index drawings_with_file_idx
  on drawings (created_at desc, id desc)
  where storage_key is not null;
