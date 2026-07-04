# SPNet Packet Forge Arena — ARP MVP corregido

Este paquete deja lista la primera base para partir con **ARP Practical Analyst Lab**.

## Qué se corrigió del paquete original

1. **Respuestas por intento**
   - Antes: `grading.answer_keys(question_id)`.
   - Ahora: `grading.answer_keys(attempt_id, question_id)`.
   - Esto permite PCAP distinto por usuario/seed.

2. **Intentos no insertables desde el navegador**
   - Se eliminó el `grant insert` y la policy de insert sobre `public.attempts`.
   - El único camino para crear intento es `public.start_attempt()`.

3. **Certificado con HMAC**
   - Se reemplazó el hash simple por firma HMAC-SHA256.
   - El secreto queda en `grading.certificate_secret`, inaccesible para `anon/authenticated`.

## Archivos

```text
supabase/01_schema_fixed.sql       Tablas corregidas
supabase/02_rls_fixed.sql          RLS corregido
supabase/03_functions_fixed.sql    Funciones corregidas
supabase/04_seed_arp_lab.sql       Lab ARP con 40 desafíos
generator/generar_arp_lab.py       Generador PCAPNG ARP parametrizado
output/arp_lab_seed42.pcapng       Captura ARP de prueba
output/arp_lab_seed42.answers.json Respuestas por ordinal para cargar en BD
output/arp_lab_seed42.events.tsv   Mapa técnico de tramas para instructor
```

## Orden de carga en Supabase

```text
1. 01_schema_fixed.sql
2. 02_rls_fixed.sql
3. 03_functions_fixed.sql
4. 04_seed_arp_lab.sql
```

## Flujo MVP

```text
1. Usuario inicia lab ARP.
2. Frontend llama public.start_attempt(lab_id).
3. Backend recibe attempt_id + seed.
4. Backend ejecuta generar_arp_lab.py con ese seed.
5. Backend sube el PCAPNG a storage.
6. Backend llama public.load_answer_keys_for_attempt(attempt_id, answers_json).
7. Usuario responde desafíos.
8. public.submit_answer() valida sin revelar respuestas.
9. public.finish_attempt() calcula puntaje y emite certificado si corresponde.
```

## Ejemplo para generar una captura

```bash
python generator/generar_arp_lab.py --seed 42 --out output/arp_lab_seed42.pcapng
```

## Ejemplo conceptual para cargar respuestas

El JSON generado tiene esta forma:

```json
[
  {"ordinal": 1, "answer": "57"},
  {"ordinal": 2, "answer": "35"}
]
```

La Edge Function debe llamar:

```js
await supabaseAdmin.rpc('load_answer_keys_for_attempt', {
  p_attempt_id: attemptId,
  p_answers: answersJson
})
```

Usar siempre service role en el backend, nunca en el navegador.

## Lab ARP inicial

- 40 desafíos.
- 57 tramas ARP en la captura de prueba.
- Incluye resolución normal, broadcast/unicast, gratuitous ARP, conflicto de IP, ARP scan, proxy ARP, probing y ARP spoofing.
- No se entregan filtros en las preguntas.
