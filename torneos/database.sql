-- Esquema inicial para Cancha / Torneos.
-- Ejecutar en Supabase > SQL Editor, luego de crear el proyecto.
-- Los administradores se asignan manualmente desde Auth; los usuarios nuevos
-- quedan en estado pending hasta que un super_admin los habilite.

create table if not exists public.courts (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  court_id uuid references public.courts(id) on delete cascade,
  display_name text,
  role text not null default 'pending'
    check (role in ('pending', 'super_admin', 'court_admin')),
  created_at timestamptz not null default now(),
  constraint profiles_role_court_check check (
    (role = 'court_admin' and court_id is not null)
    or (role in ('pending', 'super_admin') and court_id is null)
  )
);

create table if not exists public.tournaments (
  id uuid primary key default gen_random_uuid(),
  court_id uuid not null references public.courts(id) on delete cascade,
  name text not null,
  season text,
  round_format text not null default 'single' check (round_format in ('single', 'double')),
  qualifiers smallint not null default 4 check (qualifiers in (0, 4)),
  points_win smallint not null default 3 check (points_win between 0 and 10),
  points_draw smallint not null default 1 check (points_draw between 0 and 10),
  points_loss smallint not null default 0 check (points_loss between 0 and 10),
  is_public boolean not null default true,
  public_code text not null unique default replace(gen_random_uuid()::text, '-', ''),
  app_data jsonb not null default '{"config":{"doubleRound":false,"qualifiers":4,"winPoints":3,"drawPoints":1,"lossPoints":0},"data":{"teams":[],"matches":[],"playoffs":{}}}'::jsonb,
  created_at timestamptz not null default now()
);

alter table public.tournaments add column if not exists app_data jsonb not null
  default '{"config":{"doubleRound":false,"qualifiers":4,"winPoints":3,"drawPoints":1,"lossPoints":0},"data":{"teams":[],"matches":[],"playoffs":{}}}'::jsonb;

create table if not exists public.teams (
  id uuid primary key default gen_random_uuid(),
  tournament_id uuid not null references public.tournaments(id) on delete cascade,
  name text not null,
  created_at timestamptz not null default now(),
  unique (tournament_id, id),
  unique (tournament_id, name)
);

create table if not exists public.matches (
  id uuid primary key default gen_random_uuid(),
  tournament_id uuid not null references public.tournaments(id) on delete cascade,
  round_number integer not null default 1,
  stage text not null default 'league' check (stage in ('league', 'semi1', 'semi2', 'final')),
  home_team_id uuid not null,
  away_team_id uuid not null,
  home_score smallint check (home_score is null or home_score >= 0),
  away_score smallint check (away_score is null or away_score >= 0),
  scheduled_at timestamptz,
  created_at timestamptz not null default now(),
  constraint matches_different_teams check (home_team_id <> away_team_id),
  constraint matches_home_team_in_tournament foreign key (tournament_id, home_team_id)
    references public.teams(tournament_id, id) on delete cascade,
  constraint matches_away_team_in_tournament foreign key (tournament_id, away_team_id)
    references public.teams(tournament_id, id) on delete cascade
);

create index if not exists tournaments_court_id_idx on public.tournaments(court_id);
create index if not exists teams_tournament_id_idx on public.teams(tournament_id);
create index if not exists matches_tournament_id_idx on public.matches(tournament_id);

-- Privilege checks run as the table owner to avoid recursive RLS checks.
create or replace function public.is_super_admin()
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles p
    where p.user_id = auth.uid() and p.role = 'super_admin'
  );
$$;

create or replace function public.can_manage_court(target_court_id uuid)
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles p
    where p.user_id = auth.uid()
      and (p.role = 'super_admin' or (p.role = 'court_admin' and p.court_id = target_court_id))
  );
$$;

create or replace function public.can_manage_tournament(target_tournament_id uuid)
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.tournaments t
    where t.id = target_tournament_id and public.can_manage_court(t.court_id)
  );
$$;

grant execute on function public.is_super_admin() to anon, authenticated;
grant execute on function public.can_manage_court(uuid) to anon, authenticated;
grant execute on function public.can_manage_tournament(uuid) to anon, authenticated;

-- Create a restricted profile for each newly registered app user.
create or replace function public.handle_new_app_user()
returns trigger
language plpgsql security definer
set search_path = public
as $$
begin
  insert into public.profiles (user_id, display_name, role)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'full_name', new.email), 'pending')
  on conflict (user_id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_torneos on auth.users;
create trigger on_auth_user_created_torneos
  after insert on auth.users
  for each row execute function public.handle_new_app_user();

alter table public.courts enable row level security;
alter table public.profiles enable row level security;
alter table public.tournaments enable row level security;
alter table public.teams enable row level security;
alter table public.matches enable row level security;

grant usage on schema public to anon, authenticated;
grant select on public.courts, public.tournaments, public.teams, public.matches to anon, authenticated;
grant insert, update, delete on public.courts, public.tournaments, public.teams, public.matches to authenticated;
grant select, insert, update, delete on public.profiles to authenticated;

drop policy if exists "read court for admins or public tournaments" on public.courts;
create policy "read court for admins or public tournaments" on public.courts
  for select to anon, authenticated
  using (public.can_manage_court(id) or exists (
    select 1 from public.tournaments t where t.court_id = id and t.is_public
  ));
drop policy if exists "super admins create courts" on public.courts;
create policy "super admins create courts" on public.courts
  for insert to authenticated with check (public.is_super_admin());
drop policy if exists "super admins update courts" on public.courts;
create policy "super admins update courts" on public.courts
  for update to authenticated using (public.is_super_admin()) with check (public.is_super_admin());
drop policy if exists "super admins delete courts" on public.courts;
create policy "super admins delete courts" on public.courts
  for delete to authenticated using (public.is_super_admin());

drop policy if exists "read own profile or super admin" on public.profiles;
create policy "read own profile or super admin" on public.profiles
  for select to authenticated using (user_id = auth.uid() or public.is_super_admin());
drop policy if exists "super admins manage profiles" on public.profiles;
create policy "super admins manage profiles" on public.profiles
  for all to authenticated using (public.is_super_admin()) with check (public.is_super_admin());

drop policy if exists "read public or own tournaments" on public.tournaments;
create policy "read public or own tournaments" on public.tournaments
  for select to anon, authenticated
  using (is_public or public.can_manage_court(court_id));
drop policy if exists "court admins create tournaments" on public.tournaments;
create policy "court admins create tournaments" on public.tournaments
  for insert to authenticated with check (public.can_manage_court(court_id));
drop policy if exists "court admins update tournaments" on public.tournaments;
create policy "court admins update tournaments" on public.tournaments
  for update to authenticated using (public.can_manage_court(court_id))
  with check (public.can_manage_court(court_id));
drop policy if exists "court admins delete tournaments" on public.tournaments;
create policy "court admins delete tournaments" on public.tournaments
  for delete to authenticated using (public.can_manage_court(court_id));

drop policy if exists "read public or own teams" on public.teams;
create policy "read public or own teams" on public.teams
  for select to anon, authenticated
  using (exists (select 1 from public.tournaments t where t.id = tournament_id
    and (t.is_public or public.can_manage_court(t.court_id))));
drop policy if exists "admins create teams" on public.teams;
create policy "admins create teams" on public.teams
  for insert to authenticated with check (public.can_manage_tournament(tournament_id));
drop policy if exists "admins update teams" on public.teams;
create policy "admins update teams" on public.teams
  for update to authenticated using (public.can_manage_tournament(tournament_id))
  with check (public.can_manage_tournament(tournament_id));
drop policy if exists "admins delete teams" on public.teams;
create policy "admins delete teams" on public.teams
  for delete to authenticated using (public.can_manage_tournament(tournament_id));

drop policy if exists "read public or own matches" on public.matches;
create policy "read public or own matches" on public.matches
  for select to anon, authenticated
  using (exists (select 1 from public.tournaments t where t.id = tournament_id
    and (t.is_public or public.can_manage_court(t.court_id))));
drop policy if exists "admins create matches" on public.matches;
create policy "admins create matches" on public.matches
  for insert to authenticated with check (public.can_manage_tournament(tournament_id));
drop policy if exists "admins update matches" on public.matches;
create policy "admins update matches" on public.matches
  for update to authenticated using (public.can_manage_tournament(tournament_id))
  with check (public.can_manage_tournament(tournament_id));
drop policy if exists "admins delete matches" on public.matches;
create policy "admins delete matches" on public.matches
  for delete to authenticated using (public.can_manage_tournament(tournament_id));

-- Enable row-change subscriptions for tournament views, if the publication exists.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'tournaments') then
      alter publication supabase_realtime add table public.tournaments;
    end if;
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'teams') then
      alter publication supabase_realtime add table public.teams;
    end if;
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'matches') then
      alter publication supabase_realtime add table public.matches;
    end if;
  end if;
end $$;

-- Initial owner setup, to run only after creating your first user in Supabase Auth:
-- update public.profiles p
-- set role = 'super_admin', court_id = null
-- from auth.users u
-- where u.id = p.user_id and u.email = 'TU_EMAIL_DE_SUPABASE';

