-- Seed data, so there is something to render before uploads exist.
--
-- Honest caveat: seed data in a schema migration is a shortcut. Real projects
-- keep them apart, because migrations are structural facts that must run
-- everywhere, while seeds are environment-dependent (you want fixtures in dev
-- and emphatically not in prod). It is defensible here only because this row
-- set is demo scaffolding that we want identical in both places, and Stage 2
-- will replace it with real uploads.
--
-- No ON CONFLICT needed: the runner records which files it has applied, so
-- this executes exactly once per database.

insert into drawings (title, artist, year, rating) values
  ('Vitruvian Man',              'Leonardo da Vinci',   1490, 4.9),
  ('Study of Hands',             'Albrecht Durer',      1508, 4.7),
  ('The Great Wave sketch',      'Katsushika Hokusai',  1830, 4.8),
  ('Head of a Woman',            'Pablo Picasso',       1907, 4.2),
  ('Melencolia I study',         'Albrecht Durer',      1514, 4.5),
  ('Self-portrait in charcoal',  'Kathe Kollwitz',      1924, 4.6),
  ('Nocturne study',             'James McNeill Whistler', 1872, 3.9),
  ('Untitled figure study',      'Anonymous',           1961, null);
