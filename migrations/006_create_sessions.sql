-- A session, made physical.
--
-- "Logged in" is not a state the server remembers about you. HTTP has no
-- memory: every request arrives alone, from nowhere, with no relationship to
-- the one before it. A session is the thing we invent to fake continuity — and
-- in this design it is exactly this: A ROW IN A TABLE, plus a random string the
-- client sends back to name that row.
--
-- That is the whole trick. Nothing more mysterious is happening.
--
-- Stage 4a builds the row. Stage 4b is the genuinely hard half: how the string
-- gets to the browser and back across two different hostnames.

create table sessions (
  -- The primary key is NOT the token. It is just a row id, safe to log, safe to
  -- print in an error message, safe to show in an admin screen.
  id            uuid        primary key default gen_random_uuid(),

  -- The SHA-256 of the token we handed out — never the token itself.
  --
  -- Same reasoning as the password column, one step further: if this table
  -- leaks, the attacker gets a pile of hashes, and a hash cannot be replayed.
  -- Sending it back does not log you in, because the server hashes what arrives
  -- and compares — so a stolen hash would have to be un-hashed first.
  --
  -- Why a FAST hash here, when passwords demand a deliberately slow one?
  -- Because slowness in password hashing exists solely to defeat GUESSING, and
  -- guessing only works against something guessable. A password is chosen by a
  -- human out of a space attackers have catalogued. This token is 256 bits from
  -- the operating system's CSPRNG — there is no dictionary of those, and no
  -- amount of hardware brute-forces it. Slow hashing would buy nothing and cost
  -- CPU on literally every authenticated request.
  --
  -- The rule: slow hashing protects LOW-ENTROPY secrets. High-entropy secrets
  -- need only a fast one-way function.
  token_hash    text        not null unique,

  -- A real foreign key, with a real cascade. Deleting a user must not leave
  -- sessions pointing at nobody: that is the dangling-reference problem, and
  -- here the database can enforce the answer itself rather than trusting some
  -- future DELETE handler to remember.
  user_id       uuid        not null references users (id) on delete cascade,

  created_at    timestamptz not null default now(),

  -- Expiry is stored, not computed from created_at in application code.
  --
  -- Storing the deadline instead of the duration means changing the policy
  -- later ("30 days now, not 7") does not silently extend every session already
  -- issued. Each row keeps the promise it was created with.
  expires_at    timestamptz not null,

  -- Set on each successful use. Not required for correctness; it is what makes
  -- "log out my other devices" and "last active 3 days ago" possible, and it is
  -- how you would notice a session being used from somewhere unexpected.
  last_seen_at  timestamptz
);

-- Login inserts, every authenticated request selects by token_hash. That lookup
-- is served by the UNIQUE constraint above, which is a btree index — so no
-- extra index for it.
--
-- This one exists for the other direction: "all sessions belonging to this
-- user", which is logout-everywhere, and the sweep that deletes a deleted
-- user's sessions.
create index sessions_user_id_idx on sessions (user_id);

-- Expired rows are not removed by anything yet.
--
-- Deliberate, and worth being honest about: expiry is enforced when a session
-- is USED (the query demands expires_at > now()), so an expired row is already
-- harmless — it just takes up space. Cleaning it up is housekeeping, not
-- security, and housekeeping needs a scheduled job that this project does not
-- have yet. Listed in CLAUDE.md with the other dated shortcuts.
create index sessions_expires_at_idx on sessions (expires_at);
