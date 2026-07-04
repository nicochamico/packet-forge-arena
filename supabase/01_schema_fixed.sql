-- =============================================================================
-- SPNet Packet Forge Arena — Esquema corregido MVP
-- Archivo 1 de 4: TABLAS
-- =============================================================================
-- Correcciones aplicadas:
--   1) Las claves de respuesta son por intento: (attempt_id, question_id).
--   2) Los intentos no se crean desde el navegador; solo con start_attempt().
--   3) Certificados firmados con HMAC usando secreto guardado en grading.
-- =============================================================================

create extension if not exists "pgcrypto";
create schema if not exists grading;

-- =============================================================================
-- 1. PERFILES
-- =============================================================================
create table if not exists public.profiles (
  id            uuid primary key references auth.users(id) on delete cascade,
  display_name  text not null,
  email         text,
  country       text,
  created_at    timestamptz not null default now(),
  is_admin      boolean not null default false
);

-- =============================================================================
-- 2. LABS
-- =============================================================================
create table if not exists public.labs (
  id             uuid primary key default gen_random_uuid(),
  slug           text unique not null,
  title          text not null,
  description    text,
  protocol       text not null,
  difficulty     text not null default 'intermediate',
  question_count int  not null default 0,
  pass_threshold int  not null default 80,
  time_limit_min int,
  max_attempts   int  not null default 3,
  is_published   boolean not null default false,
  is_exam        boolean not null default false,
  created_at     timestamptz not null default now()
);

-- =============================================================================
-- 3. PREGUNTAS PÚBLICAS, SIN RESPUESTA
-- =============================================================================
create table if not exists public.questions (
  id             uuid primary key default gen_random_uuid(),
  lab_id         uuid not null references public.labs(id) on delete cascade,
  ordinal        int  not null,
  block          text,
  prompt         text not null,
  hint_filter    text,
  points         int  not null default 10,
  answer_type    text not null default 'exact',
  is_active      boolean not null default true,
  created_at     timestamptz not null default now(),
  unique (lab_id, ordinal)
);

-- =============================================================================
-- 4. INTENTOS
-- =============================================================================
create table if not exists public.attempts (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid not null references public.profiles(id) on delete cascade,
  lab_id         uuid not null references public.labs(id) on delete cascade,
  seed           bigint not null,
  status         text not null default 'in_progress',
  started_at     timestamptz not null default now(),
  submitted_at   timestamptz,
  score_pct      numeric,
  points_earned  int,
  points_total   int,
  passed         boolean,
  level          text,
  attempt_number int not null default 1,
  unique (user_id, lab_id, attempt_number)
);

-- =============================================================================
-- 5. RESPUESTAS SECRETAS POR INTENTO
-- =============================================================================
-- Clave corregida: la respuesta depende del seed, por lo tanto depende del intento.
create table if not exists grading.answer_keys (
  attempt_id     uuid not null references public.attempts(id) on delete cascade,
  question_id    uuid not null references public.questions(id) on delete cascade,
  answer_hashes  text[] not null,
  answer_plain   text,
  tolerance      numeric,
  regex_pattern  text,
  updated_at     timestamptz not null default now(),
  primary key (attempt_id, question_id)
);

-- Secreto HMAC para firmar certificados. No exponer a anon/authenticated.
create table if not exists grading.certificate_secret (
  id             int primary key default 1 check (id = 1),
  secret         text not null,
  created_at     timestamptz not null default now()
);

insert into grading.certificate_secret (id, secret)
values (1, encode(gen_random_bytes(32), 'hex'))
on conflict (id) do nothing;

-- =============================================================================
-- 6. RESPUESTAS DEL USUARIO
-- =============================================================================
create table if not exists public.submissions (
  id             uuid primary key default gen_random_uuid(),
  attempt_id     uuid not null references public.attempts(id) on delete cascade,
  question_id    uuid not null references public.questions(id) on delete cascade,
  user_id        uuid not null references public.profiles(id) on delete cascade,
  answer_given   text not null,
  is_correct     boolean not null,
  points_awarded int not null default 0,
  answered_at    timestamptz not null default now(),
  unique (attempt_id, question_id)
);

-- =============================================================================
-- 7. CERTIFICADOS
-- =============================================================================
create table if not exists public.certificates (
  id             uuid primary key default gen_random_uuid(),
  public_code    text unique not null,
  user_id        uuid not null references public.profiles(id) on delete cascade,
  lab_id         uuid not null references public.labs(id) on delete cascade,
  attempt_id     uuid not null references public.attempts(id) on delete cascade,
  holder_name    text not null,
  lab_title      text not null,
  score_pct      numeric not null,
  level          text not null,
  attempts_used  int not null,
  issued_at      timestamptz not null default now(),
  signature      text not null
);

-- =============================================================================
-- 8. RANKING
-- =============================================================================
create or replace view public.leaderboard
with (security_invoker = true)
as
select
  a.lab_id,
  l.slug            as lab_slug,
  p.display_name,
  p.country,
  max(a.score_pct)  as best_score,
  min(a.attempt_number) filter (where a.passed) as attempts_to_pass,
  bool_or(a.passed) as has_passed
from public.attempts a
join public.profiles p on p.id = a.user_id
join public.labs     l on l.id = a.lab_id
where a.status = 'submitted'
group by a.lab_id, l.slug, p.display_name, p.country;

create index if not exists idx_questions_lab       on public.questions(lab_id);
create index if not exists idx_attempts_user       on public.attempts(user_id);
create index if not exists idx_attempts_lab        on public.attempts(lab_id);
create index if not exists idx_submissions_attempt on public.submissions(attempt_id);
create index if not exists idx_submissions_user    on public.submissions(user_id);
create index if not exists idx_certificates_user   on public.certificates(user_id);
create index if not exists idx_certificates_code   on public.certificates(public_code);
