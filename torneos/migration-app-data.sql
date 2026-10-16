-- Actualización para habilitar la sincronización de la app con Supabase.
-- Se puede ejecutar en proyectos que ya tengan instalado database.sql.
alter table public.tournaments
  add column if not exists app_data jsonb not null
  default '{"config":{"doubleRound":false,"qualifiers":4,"winPoints":3,"drawPoints":1,"lossPoints":0},"data":{"teams":[],"matches":[],"playoffs":{}}}'::jsonb;

-- La app y Supabase Realtime usan la fila del torneo como fuente compartida.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'tournaments') then
    alter publication supabase_realtime add table public.tournaments;
  end if;
end $$;

