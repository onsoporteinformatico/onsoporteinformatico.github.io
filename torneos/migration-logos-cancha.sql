-- Permite que cada cancha tenga su propio logo.
alter table public.courts add column if not exists logo_url text;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('court-logos', 'court-logos', true, 2097152, array['image/png','image/jpeg','image/webp'])
on conflict (id) do update
set public = excluded.public,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "public read court logos" on storage.objects;
create policy "public read court logos" on storage.objects
  for select to anon, authenticated
  using (bucket_id = 'court-logos');

drop policy if exists "admins upload own court logos" on storage.objects;
create policy "admins upload own court logos" on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'court-logos'
    and public.can_manage_court((storage.foldername(name))[1]::uuid)
  );

drop policy if exists "admins update own court logos" on storage.objects;
create policy "admins update own court logos" on storage.objects
  for update to authenticated
  using (
    bucket_id = 'court-logos'
    and public.can_manage_court((storage.foldername(name))[1]::uuid)
  )
  with check (
    bucket_id = 'court-logos'
    and public.can_manage_court((storage.foldername(name))[1]::uuid)
  );

drop policy if exists "admins delete own court logos" on storage.objects;
create policy "admins delete own court logos" on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'court-logos'
    and public.can_manage_court((storage.foldername(name))[1]::uuid)
  );

create or replace function public.set_court_logo(target_court_id uuid, target_logo_url text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.can_manage_court(target_court_id) then
    raise exception 'No tenés permiso para cambiar el logo de esta cancha';
  end if;

  update public.courts
  set logo_url = nullif(btrim(target_logo_url), '')
  where id = target_court_id;

  if not found then
    raise exception 'No se encontró la cancha';
  end if;
end;
$$;

revoke all on function public.set_court_logo(uuid, text) from public;
grant execute on function public.set_court_logo(uuid, text) to authenticated;

-- Sincroniza el cambio de logo en las sesiones abiertas.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'courts') then
    alter publication supabase_realtime add table public.courts;
  end if;
end $$;

