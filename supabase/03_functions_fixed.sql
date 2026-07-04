create extension if not exists "pgcrypto" with schema extensions;

-- =============================================================================
-- SPNet Packet Forge Arena — Funciones corregidas
-- Archivo 3 de 4
-- =============================================================================

create or replace function grading.normalize_answer(raw text)
returns text
language sql
immutable
as $$
  select regexp_replace(
           regexp_replace(
             regexp_replace(lower(trim(coalesce(raw,''))), '^(as|as-|vlan|vlan-)?\s*', '', 'g'),
             '\s+', '', 'g'
           ),
           ';', ',', 'g'
         );
$$;

create or replace function grading.hash_answer(raw text)
returns text
language sql
immutable
as $$
  select encode(extensions.digest(grading.normalize_answer(raw), 'sha256'::text), 'hex');
$$;

create or replace function grading.certificate_payload(
  p_code text,
  p_holder text,
  p_lab text,
  p_score numeric,
  p_level text,
  p_attempts int,
  p_issued timestamptz
)
returns text
language sql
immutable
as $$
  select concat_ws('|', upper(p_code), p_holder, p_lab, p_score::text, p_level, p_attempts::text, p_issued::text);
$$;

create or replace function grading.sign_certificate_payload(p_payload text)
returns text
language sql
stable
security definer
set search_path = grading, public
as $$
  select encode(extensions.hmac(convert_to(p_payload, 'utf8'), convert_to(secret, 'utf8'), 'sha256'::text), 'hex')
  from grading.certificate_secret
  where id = 1;
$$;

revoke all on function grading.sign_certificate_payload(text) from public;

-- -----------------------------------------------------------------------------
-- start_attempt(): único camino para crear intentos.
-- -----------------------------------------------------------------------------
create or replace function public.start_attempt(p_lab_id uuid)
returns table (attempt_id uuid, seed bigint, attempt_number int)
language plpgsql
security definer
set search_path = public, grading
as $$
declare
  v_uid    uuid := (select auth.uid());
  v_lab    public.labs%rowtype;
  v_used   int;
  v_seed   bigint;
  v_id     uuid;
begin
  if v_uid is null then raise exception 'No autenticado'; end if;

  select * into v_lab
  from public.labs
  where id = p_lab_id and is_published;

  if not found then raise exception 'Lab no disponible'; end if;

  select count(*) into v_used
  from public.attempts
  where user_id = v_uid and lab_id = p_lab_id;

  if v_used >= v_lab.max_attempts then
    raise exception 'Sin intentos restantes';
  end if;

  v_seed := ('x' || substr(encode(extensions.digest(v_uid::text || p_lab_id::text || (v_used+1)::text, 'sha256'::text),'hex'), 1, 15))::bit(60)::bigint;

  insert into public.attempts (user_id, lab_id, seed, attempt_number)
  values (v_uid, p_lab_id, v_seed, v_used + 1)
  returning id into v_id;

  return query select v_id, v_seed, v_used + 1;
end;
$$;

revoke all on function public.start_attempt(uuid) from public;
grant execute on function public.start_attempt(uuid) to authenticated;

-- -----------------------------------------------------------------------------
-- load_answer_keys_for_attempt(): la Edge Function/service_role carga las claves
-- del intento después de generar el PCAP con el seed.
-- Espera JSON: [{"ordinal":1,"answer":"..."}, ...]
-- -----------------------------------------------------------------------------
create or replace function public.load_answer_keys_for_attempt(
  p_attempt_id uuid,
  p_answers jsonb
)
returns int
language plpgsql
security definer
set search_path = public, grading
as $$
declare
  v_attempt public.attempts%rowtype;
  v_count int := 0;
  r jsonb;
  v_question_id uuid;
  v_answer text;
begin
  select * into v_attempt from public.attempts where id = p_attempt_id;
  if not found then raise exception 'Intento no encontrado'; end if;

  for r in select * from jsonb_array_elements(p_answers)
  loop
    select q.id into v_question_id
    from public.questions q
    where q.lab_id = v_attempt.lab_id
      and q.ordinal = (r->>'ordinal')::int
      and q.is_active;

    if v_question_id is null then
      raise exception 'Pregunta ordinal % no encontrada para el intento', r->>'ordinal';
    end if;

    v_answer := r->>'answer';

    insert into grading.answer_keys (attempt_id, question_id, answer_hashes, answer_plain)
    values (p_attempt_id, v_question_id, array[grading.hash_answer(v_answer)], v_answer)
    on conflict (attempt_id, question_id) do update
      set answer_hashes = excluded.answer_hashes,
          answer_plain = excluded.answer_plain,
          updated_at = now();

    v_count := v_count + 1;
  end loop;

  return v_count;
end;
$$;

revoke all on function public.load_answer_keys_for_attempt(uuid, jsonb) from public;
grant execute on function public.load_answer_keys_for_attempt(uuid, jsonb) to service_role;

-- -----------------------------------------------------------------------------
-- submit_answer(): valida contra grading.answer_keys usando attempt_id + question_id.
-- -----------------------------------------------------------------------------
create or replace function public.submit_answer(
  p_attempt_id uuid,
  p_question_id uuid,
  p_answer text
)
returns table (is_correct boolean, points_awarded int)
language plpgsql
security definer
set search_path = public, grading
as $$
declare
  v_uid          uuid := (select auth.uid());
  v_attempt      public.attempts%rowtype;
  v_question     public.questions%rowtype;
  v_key          grading.answer_keys%rowtype;
  v_correct      boolean := false;
  v_points       int := 0;
  v_given_hash   text;
begin
  if v_uid is null then raise exception 'No autenticado'; end if;

  select * into v_attempt
  from public.attempts
  where id = p_attempt_id and user_id = v_uid;

  if not found then raise exception 'Intento no encontrado o ajeno'; end if;
  if v_attempt.status <> 'in_progress' then raise exception 'El intento ya fue enviado'; end if;

  select * into v_question
  from public.questions
  where id = p_question_id and lab_id = v_attempt.lab_id and is_active;

  if not found then raise exception 'Pregunta invalida para este lab'; end if;

  if exists (select 1 from public.submissions where attempt_id = p_attempt_id and question_id = p_question_id) then
    raise exception 'Pregunta ya respondida';
  end if;

  select * into v_key
  from grading.answer_keys
  where attempt_id = p_attempt_id and question_id = p_question_id;

  if not found then raise exception 'Sin clave de respuesta configurada para este intento'; end if;

  if v_question.answer_type = 'numeric' then
    v_correct := abs(grading.normalize_answer(p_answer)::numeric - grading.normalize_answer(v_key.answer_plain)::numeric) <= coalesce(v_key.tolerance, 0);
  elsif v_question.answer_type = 'regex' then
    v_correct := grading.normalize_answer(p_answer) ~ v_key.regex_pattern;
  else
    v_given_hash := grading.hash_answer(p_answer);
    v_correct := v_given_hash = any(v_key.answer_hashes);
  end if;

  if v_correct then v_points := v_question.points; end if;

  insert into public.submissions (attempt_id, question_id, user_id, answer_given, is_correct, points_awarded)
  values (p_attempt_id, p_question_id, v_uid, p_answer, v_correct, v_points);

  return query select v_correct, v_points;
end;
$$;

revoke all on function public.submit_answer(uuid, uuid, text) from public;
grant execute on function public.submit_answer(uuid, uuid, text) to authenticated;

-- -----------------------------------------------------------------------------
-- finish_attempt(): cierra, calcula y emite certificado con HMAC.
-- -----------------------------------------------------------------------------
create or replace function public.finish_attempt(p_attempt_id uuid)
returns table (score_pct numeric, passed boolean, level text, certificate_code text)
language plpgsql
security definer
set search_path = public, grading
as $$
declare
  v_uid        uuid := (select auth.uid());
  v_attempt    public.attempts%rowtype;
  v_lab        public.labs%rowtype;
  v_prof       public.profiles%rowtype;
  v_earned     int;
  v_total      int;
  v_pct        numeric;
  v_passed     boolean;
  v_level      text;
  v_code       text := null;
  v_issued     timestamptz;
  v_payload    text;
  v_signature  text;
begin
  if v_uid is null then raise exception 'No autenticado'; end if;

  select * into v_attempt
  from public.attempts
  where id = p_attempt_id and user_id = v_uid
  for update;

  if not found then raise exception 'Intento no encontrado'; end if;
  if v_attempt.status <> 'in_progress' then raise exception 'Intento ya cerrado'; end if;

  select * into v_lab from public.labs where id = v_attempt.lab_id;
  select * into v_prof from public.profiles where id = v_uid;

  select coalesce(sum(points_awarded),0) into v_earned
  from public.submissions
  where attempt_id = p_attempt_id;

  select coalesce(sum(points),0) into v_total
  from public.questions
  where lab_id = v_attempt.lab_id and is_active;

  v_pct := case when v_total > 0 then round(100.0 * v_earned / v_total, 1) else 0 end;
  v_passed := v_pct >= v_lab.pass_threshold;

  v_level := case
    when v_pct >= 95 then 'elite'
    when v_pct >= 90 then 'alto desempeno'
    when v_pct >= 85 then 'destacado'
    when v_pct >= v_lab.pass_threshold then 'aprobado'
    else 'no aprobado'
  end;

  update public.attempts
    set status = 'submitted',
        submitted_at = now(),
        score_pct = v_pct,
        points_earned = v_earned,
        points_total = v_total,
        passed = v_passed,
        level = v_level
  where id = p_attempt_id;

  if v_passed then
    v_code := upper(substr(encode(gen_random_bytes(8), 'hex'), 1, 12));
    v_issued := now();
    v_payload := grading.certificate_payload(v_code, v_prof.display_name, v_lab.title, v_pct, v_level, v_attempt.attempt_number, v_issued);
    v_signature := grading.sign_certificate_payload(v_payload);

    insert into public.certificates
      (public_code, user_id, lab_id, attempt_id, holder_name, lab_title, score_pct, level, attempts_used, issued_at, signature)
    values
      (v_code, v_uid, v_attempt.lab_id, p_attempt_id, v_prof.display_name, v_lab.title, v_pct, v_level, v_attempt.attempt_number, v_issued, v_signature);
  end if;

  return query select v_pct, v_passed, v_level, v_code;
end;
$$;

revoke all on function public.finish_attempt(uuid) from public;
grant execute on function public.finish_attempt(uuid) to authenticated;

-- -----------------------------------------------------------------------------
-- verify_certificate(): público, pero no expone correo/user_id.
-- -----------------------------------------------------------------------------
create or replace function public.verify_certificate(p_code text)
returns table (
  holder_name text,
  lab_title text,
  score_pct numeric,
  level text,
  attempts_used int,
  issued_at timestamptz,
  valid boolean
)
language sql
security definer
set search_path = public, grading
as $$
  select c.holder_name,
         c.lab_title,
         c.score_pct,
         c.level,
         c.attempts_used,
         c.issued_at,
         c.signature = grading.sign_certificate_payload(
           grading.certificate_payload(c.public_code, c.holder_name, c.lab_title, c.score_pct, c.level, c.attempts_used, c.issued_at)
         ) as valid
  from public.certificates c
  where c.public_code = upper(p_code);
$$;

grant execute on function public.verify_certificate(text) to anon, authenticated;

-- -----------------------------------------------------------------------------
-- Trigger de perfil
-- -----------------------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, display_name, email)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email,'@',1)),
    new.email
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();
