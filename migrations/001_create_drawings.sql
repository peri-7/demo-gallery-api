-- The gallery's only table, for now.
--
-- Every column is a decision; the reasoning lives in THEORY.md §10.
-- Deliberately nothing about image files yet — storage arrives in Stage 2 as
-- its own migration, because that is how real schemas grow: by accretion,
-- in reviewable steps, never by editing history.

create table drawings (
  -- uuid rather than a sequential integer. Sequential ids are enumerable
  -- (/drawings/1, /drawings/2, ...) and leak how much data exists.
  -- gen_random_uuid() is built into Postgres 13+; no extension needed.
  id          uuid         primary key default gen_random_uuid(),

  title       text         not null check (length(trim(title))  between 1 and 120),
  artist      text         not null check (length(trim(artist)) between 1 and 80),

  -- A plain integer, not a date: we know the year a drawing was made, rarely
  -- the day. Model the precision you actually have.
  year        integer      not null check (year between 1000 and 2100),

  -- Nullable on purpose: a drawing nobody has rated yet is a real state, and
  -- 0.0 would be a lie about it. numeric, not float — see THEORY.md.
  rating      numeric(2,1)          check (rating between 0 and 5),

  -- timestamptz stores an absolute instant. Never plain `timestamp`.
  created_at  timestamptz  not null default now()
);

-- The two orderings the gallery offers.
--
-- `id desc` is a tiebreaker, not decoration: rows sharing a year have no
-- defined order without it, so two identical requests may return them in
-- different orders. Harmless on one page, fatal for pagination in Stage 3.
create index drawings_year_idx   on drawings (year desc, id desc);
create index drawings_rating_idx on drawings (rating desc nulls last, id desc);
