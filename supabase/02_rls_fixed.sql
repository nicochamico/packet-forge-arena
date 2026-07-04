-- =============================================================================
-- SPNet Packet Forge Arena — RLS corregido
-- Archivo 2 de 4
-- =============================================================================

-- Bloqueo del schema sensible
revoke all on schema grading from anon, authenticated;
revoke all on all tables in schema grading from anon, authenticated;
alter default privileges in schema grading revoke all on tables from anon, authenticated;

grant usage on schema public to anon, authenticated;

-- Grants públicos mínimos
grant select on public.labs         to authenticated;
grant select on public.questions    to authenticated;
grant select on public.attempts     to authenticated;
grant select on public.submissions  to authenticated;
grant select on public.certificates to authenticated;
grant select on public.profiles     to authenticated;
grant update on public.profiles     to authenticated;
grant select on public.leaderboard  to authenticated;

-- Importante: NO grant insert/update/delete en attempts/submissions/certificates.
-- Todo eso lo hacen funciones SECURITY DEFINER.
revoke insert, update, delete on public.attempts    from anon, authenticated;
revoke insert, update, delete on public.submissions from anon, authenticated;
revoke insert, update, delete on public.certificates from anon, authenticated;

-- service_role puede cargar respuestas generadas por seed
grant usage on schema grading to service_role;
grant all on all tables in schema grading to service_role;

-- =============================================================================
-- profiles
-- =============================================================================
alter table public.profiles enable row level security;

drop policy if exists profiles_select_own on public.profiles;
create policy profiles_select_own
  on public.profiles for select to authenticated
  using ((select auth.uid()) = id);

drop policy if exists profiles_update_own on public.profiles;
create policy profiles_update_own
  on public.profiles for update to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

-- =============================================================================
-- labs
-- =============================================================================
alter table public.labs enable row level security;

drop policy if exists labs_select_published on public.labs;
create policy labs_select_published
  on public.labs for select to authenticated
  using (is_published = true);

-- =============================================================================
-- questions
-- =============================================================================
alter table public.questions enable row level security;

drop policy if exists questions_select_active on public.questions;
create policy questions_select_active
  on public.questions for select to authenticated
  using (
    is_active = true
    and lab_id in (select id from public.labs where is_published = true)
  );

-- =============================================================================
-- attempts
-- =============================================================================
alter table public.attempts enable row level security;

drop policy if exists attempts_select_own on public.attempts;
create policy attempts_select_own
  on public.attempts for select to authenticated
  using ((select auth.uid()) = user_id);

-- No insert policy: el usuario NO puede crear intentos manualmente.
drop policy if exists attempts_insert_own on public.attempts;

-- =============================================================================
-- submissions
-- =============================================================================
alter table public.submissions enable row level security;

drop policy if exists submissions_select_own on public.submissions;
create policy submissions_select_own
  on public.submissions for select to authenticated
  using ((select auth.uid()) = user_id);

-- =============================================================================
-- certificates
-- =============================================================================
alter table public.certificates enable row level security;

drop policy if exists certificates_select_own on public.certificates;
create policy certificates_select_own
  on public.certificates for select to authenticated
  using ((select auth.uid()) = user_id);
