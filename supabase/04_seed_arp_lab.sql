-- =============================================================================
-- SPNet Packet Forge Arena — ARP Practical Analyst
-- Archivo 4 de 4: lab inicial con 40 desafíos
-- =============================================================================

with lab as (
  insert into public.labs
    (slug, title, description, protocol, difficulty, question_count, pass_threshold, time_limit_min, max_attempts, is_published, is_exam)
  values
    ('arp',
     'ARP Practical Analyst Lab',
     'Laboratorio práctico de ARP: resolución, gratuitous ARP, proxy ARP, scanning, conflictos y spoofing.',
     'ARP',
     'beginner',
     40,
     80,
     45,
     2,
     true,
     false)
  on conflict (slug) do update set
    title = excluded.title,
    description = excluded.description,
    protocol = excluded.protocol,
    difficulty = excluded.difficulty,
    question_count = excluded.question_count,
    pass_threshold = excluded.pass_threshold,
    time_limit_min = excluded.time_limit_min,
    max_attempts = excluded.max_attempts,
    is_published = excluded.is_published,
    is_exam = excluded.is_exam
  returning id
), q(ordinal, block, prompt, points, answer_type) as (
  values
  (1,  'Bloque A - Resolución básica', 'Indique la cantidad total de tramas ARP presentes en la captura.', 1, 'numeric'),
  (2,  'Bloque A - Resolución básica', 'Indique la cantidad total de solicitudes ARP.', 1, 'numeric'),
  (3,  'Bloque A - Resolución básica', 'Indique la cantidad total de respuestas ARP.', 1, 'numeric'),
  (4,  'Bloque A - Resolución básica', 'Indique la dirección IP del gateway usado en el escenario.', 1, 'exact'),
  (5,  'Bloque A - Resolución básica', 'Indique la dirección MAC del gateway legítimo.', 1, 'exact'),
  (6,  'Bloque A - Resolución básica', 'Indique la dirección IP del cliente principal.', 1, 'exact'),
  (7,  'Bloque A - Resolución básica', 'Indique la dirección MAC del cliente principal.', 1, 'exact'),
  (8,  'Bloque A - Resolución básica', 'Indique la IP consultada en la primera solicitud ARP de la captura.', 1, 'exact'),
  (9,  'Bloque A - Resolución básica', 'Indique la MAC que responde la primera resolución ARP exitosa.', 1, 'exact'),
  (10, 'Bloque B - Broadcast y unicast', 'Indique cuántas tramas ARP usan destino Ethernet broadcast.', 1, 'numeric'),
  (11, 'Bloque B - Broadcast y unicast', 'Indique cuántas tramas ARP usan destino Ethernet unicast.', 1, 'numeric'),
  (12, 'Bloque B - Broadcast y unicast', 'Indique cuántas tramas ARP tienen sender protocol address igual a target protocol address.', 1, 'numeric'),
  (13, 'Bloque B - Broadcast y unicast', 'Indique la IP del primer ARP donde sender protocol address es igual a target protocol address.', 1, 'exact'),
  (14, 'Bloque C - Conflicto de IP', 'Indique la IP que aparece reclamada por dos MAC distintas.', 1, 'exact'),
  (15, 'Bloque C - Conflicto de IP', 'Indique la primera MAC que reclama la IP en conflicto.', 1, 'exact'),
  (16, 'Bloque C - Conflicto de IP', 'Indique la segunda MAC que reclama la IP en conflicto.', 1, 'exact'),
  (17, 'Bloque D - ARP spoofing', 'Indique la IP del host que realiza el ARP spoofing.', 1, 'exact'),
  (18, 'Bloque D - ARP spoofing', 'Indique la MAC del host que realiza el ARP spoofing.', 1, 'exact'),
  (19, 'Bloque D - ARP spoofing', 'Indique la IP suplantada durante el ARP spoofing.', 1, 'exact'),
  (20, 'Bloque D - ARP spoofing', 'Indique la IP de la víctima principal del ARP spoofing.', 1, 'exact'),
  (21, 'Bloque D - ARP spoofing', 'Indique cuántas respuestas ARP maliciosas aparecen en el evento de spoofing.', 1, 'numeric'),
  (22, 'Bloque D - ARP spoofing', 'Indique la MAC legítima que corrige la suplantación del gateway.', 1, 'exact'),
  (23, 'Bloque E - ARP scan', 'Indique la IP del host que realiza el barrido ARP.', 1, 'exact'),
  (24, 'Bloque E - ARP scan', 'Indique la MAC del host que realiza el barrido ARP.', 1, 'exact'),
  (25, 'Bloque E - ARP scan', 'Indique la primera IP consultada durante el barrido ARP.', 1, 'exact'),
  (26, 'Bloque E - ARP scan', 'Indique la última IP consultada durante el barrido ARP.', 1, 'exact'),
  (27, 'Bloque E - ARP scan', 'Indique cuántas solicitudes del barrido no tienen respuesta.', 1, 'numeric'),
  (28, 'Bloque E - ARP scan', 'Indique una IP consultada explícitamente que no recibe respuesta.', 1, 'exact'),
  (29, 'Bloque F - Proxy ARP', 'Indique la IP remota consultada en el evento de Proxy ARP.', 1, 'exact'),
  (30, 'Bloque F - Proxy ARP', 'Indique la MAC que responde como Proxy ARP.', 1, 'exact'),
  (31, 'Bloque G - ARP probing', 'Indique la IP consultada por el host que usa sender protocol address 0.0.0.0.', 1, 'exact'),
  (32, 'Bloque G - ARP probing', 'Indique cuántas solicitudes ARP usan sender protocol address 0.0.0.0.', 1, 'numeric'),
  (33, 'Bloque G - ARP probing', 'Indique cuántos anuncios se emiten después del probing.', 1, 'numeric'),
  (34, 'Bloque G - ARP probing', 'Indique la IP anunciada después del probing.', 1, 'exact'),
  (35, 'Bloque G - ARP probing', 'Indique la MAC usada por el host que anuncia la IP después del probing.', 1, 'exact'),
  (36, 'Bloque H - Detección de anomalías', 'Indique cuántas tramas participan directamente en el conflicto de IP.', 1, 'numeric'),
  (37, 'Bloque H - Detección de anomalías', 'Indique cuántas respuestas ARP reclaman la IP del gateway.', 1, 'numeric'),
  (38, 'Bloque H - Detección de anomalías', 'Indique las dos MAC que reclaman la IP del gateway, separadas por coma.', 1, 'exact'),
  (39, 'Bloque H - Detección de anomalías', 'Indique cuántas tramas ARP involucran la MAC del cliente principal como origen o destino Ethernet.', 1, 'numeric'),
  (40, 'Bloque H - Detección de anomalías', 'Indique el número de paquete donde comienza el evento de ARP spoofing.', 1, 'numeric')
)
insert into public.questions (lab_id, ordinal, block, prompt, hint_filter, points, answer_type, is_active)
select lab.id, q.ordinal, q.block, q.prompt, null, q.points, q.answer_type, true
from lab, q
on conflict (lab_id, ordinal) do update set
  block = excluded.block,
  prompt = excluded.prompt,
  hint_filter = excluded.hint_filter,
  points = excluded.points,
  answer_type = excluded.answer_type,
  is_active = excluded.is_active;
