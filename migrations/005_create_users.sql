-- The first table that holds something about a person rather than a drawing.
--
-- The whole security posture of this table is one idea: THE DATABASE MUST NEVER
-- CONTAIN A PASSWORD. Not encrypted, not obfuscated, not "hashed with md5".
-- Encryption is reversible by whoever holds the key, and the key lives on the
-- same server as the data. What we store is the output of a one-way function
-- that is DELIBERATELY EXPENSIVE to compute, so that a stolen table is not a
-- list of logins.
--
-- Reasoning in full: THEORY.md §14.

create table users (
  id             uuid        primary key default gen_random_uuid(),

  -- text, not varchar(255). Postgres treats them identically apart from the
  -- length check, and every "maximum email length" number on the internet is
  -- someone's guess. Constrain what you actually know.
  email          text        not null check (length(email) between 3 and 254),

  -- Not "password". Not "password_encrypted". The column name is documentation:
  -- anyone reading this schema learns in one word what is and is not in here.
  --
  -- It holds a self-describing string, not a bare hash:
  --
  --     scrypt$N=16384,r=8,p=1$<salt base64>$<hash base64>
  --
  -- The parameters travel WITH the hash. This is the part people leave out and
  -- regret. Computers get faster, so the cost must be raised every few years —
  -- and if the parameters lived in the application code instead, raising them
  -- would make every existing hash unverifiable and lock out every user at
  -- once. Because each row carries the settings it was made with, an old row is
  -- still checkable with its own old cost, and can be quietly re-hashed at the
  -- new cost the next time that user logs in successfully.
  password_hash  text        not null,

  created_at     timestamptz not null default now()
);

-- Uniqueness on lower(email), not on email.
--
-- Otherwise Alice@example.com and alice@example.com are two accounts, and the
-- second one is either a confused user or a deliberate impersonation. The
-- application also lowercases on the way in — but the application is not the
-- only thing that will ever write to this table (a script, a psql session, a
-- future service). A constraint is enforced where the data lives; validation in
-- application code is enforced only where you remembered to put it. Both.
--
-- This is a FUNCTIONAL index: the thing indexed is an expression, not a column.
-- It doubles as the lookup index for login, which is why there is no second
-- index on email — a query for `where lower(email) = lower($1)` matches this
-- index exactly, and a query for `where email = $1` would not use it at all.
create unique index users_email_lower_key on users (lower(email));
