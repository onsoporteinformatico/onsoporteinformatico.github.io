-- Agenda interna de turnos por complejo.
-- Ejecutar una sola vez en Supabase > SQL Editor.
-- Solo usuarios autenticados con perfil de administrador del complejo pueden leer o modificar estos datos.

create table if not exists public.booking_resources (
  id uuid primary key default gen_random_uuid(),
  court_id uuid not null references public.courts(id) on delete cascade,
  name text not null check (length(btrim(name)) between 2 and 60),
  opens_at time not null,
  closes_at time not null,
  slot_minutes smallint not null default 60 check (slot_minutes in (30, 60, 90, 120)),
  weekdays smallint[] not null default array[0,1,2,3,4,5,6]::smallint[],
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  unique (court_id, id),
  check (opens_at < closes_at),
  check (cardinality(weekdays) between 1 and 7),
  check (weekdays <@ array[0,1,2,3,4,5,6]::smallint[])
);

create unique index if not exists booking_resources_name_per_court_idx
  on public.booking_resources (court_id, lower(name));

create table if not exists public.court_bookings (
  id uuid primary key default gen_random_uuid(),
  court_id uuid not null,
  resource_id uuid not null,
  booking_date date not null,
  starts_at time not null,
  ends_at time not null,
  customer_name text not null check (length(btrim(customer_name)) between 2 and 80),
  customer_phone text,
  notes text,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  foreign key (court_id, resource_id)
    references public.booking_resources(court_id, id) on delete restrict,
  check (starts_at < ends_at),
  check (customer_phone is null or length(customer_phone) <= 40),
  check (notes is null or length(notes) <= 240)
);

create index if not exists court_bookings_court_date_idx
  on public.court_bookings (court_id, booking_date, starts_at);
create index if not exists court_bookings_resource_date_idx
  on public.court_bookings (resource_id, booking_date, starts_at);

-- Valida horario, día y duración desde la base y evita reservas que se pisan,
-- incluso si dos administradores intentan guardar el mismo horario a la vez.
create or replace function public.validate_court_booking()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
declare
  r public.booking_resources%rowtype;
  start_offset_seconds numeric;
begin
  select * into r
  from public.booking_resources
  where id = new.resource_id and court_id = new.court_id;

  if not found then
    raise exception 'No se encontró el espacio de esta cancha';
  end if;

  if not (extract(dow from new.booking_date)::smallint = any(r.weekdays)) then
    raise exception 'El espacio no está disponible ese día';
  end if;

  if new.starts_at < r.opens_at or new.ends_at > r.closes_at then
    raise exception 'El horario está fuera del horario de atención';
  end if;

  if new.ends_at - new.starts_at <> make_interval(mins => r.slot_minutes) then
    raise exception 'La duración del turno debe coincidir con la configuración del espacio';
  end if;

  start_offset_seconds := extract(epoch from (new.starts_at - r.opens_at));
  if start_offset_seconds < 0 or mod(start_offset_seconds, r.slot_minutes * 60) <> 0 then
    raise exception 'El horario no coincide con los intervalos del espacio';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(new.resource_id::text || ':' || new.booking_date::text, 0));

  if exists (
    select 1 from public.court_bookings b
    where b.resource_id = new.resource_id
      and b.booking_date = new.booking_date
      and b.id <> new.id
      and b.starts_at < new.ends_at
      and b.ends_at > new.starts_at
  ) then
    raise exception using
      errcode = '23P01',
      message = 'Ese horario ya está reservado';
  end if;

  return new;
end;
$$;

drop trigger if exists validate_court_booking_before_write on public.court_bookings;
create trigger validate_court_booking_before_write
  before insert or update on public.court_bookings
  for each row execute function public.validate_court_booking();

alter table public.booking_resources enable row level security;
alter table public.court_bookings enable row level security;

grant select, insert, update, delete on public.booking_resources to authenticated;
grant select, insert, update, delete on public.court_bookings to authenticated;

drop policy if exists "admins manage court booking resources" on public.booking_resources;
create policy "admins manage court booking resources" on public.booking_resources
  for all to authenticated
  using (public.can_manage_court(court_id))
  with check (public.can_manage_court(court_id));

drop policy if exists "admins manage court bookings" on public.court_bookings;
create policy "admins manage court bookings" on public.court_bookings
  for all to authenticated
  using (public.can_manage_court(court_id))
  with check (public.can_manage_court(court_id));

-- No se conceden permisos a anon: los clientes no pueden consultar ni gestionar la agenda.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'booking_resources') then
      alter publication supabase_realtime add table public.booking_resources;
    end if;
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'court_bookings') then
      alter publication supabase_realtime add table public.court_bookings;
    end if;
  end if;
end $$;
