# CLAUDE.md — Polizza Facile

Contesto per Claude Code. Leggi tutto prima di modificare codice.

## Cos'è
Strumento AI per agenti assicurativi italiani. Legge il **CGA** (Condizioni Generali di Assicurazione — il fascicolo ufficiale di 50-200 pagine) di una polizza ed estrae una **tabella strutturata e confrontabile delle garanzie**: per ogni garanzia → limite/massimale, scoperto (%), franchigia (€), e stato (inclusa / opzionale / esclusa). L'agente carica uno o più CGA e ottiene un confronto affiancato. C'è anche una chat che risponde citando articoli/pagine del CGA.

Il prodotto è **neutrale**: analizza e confronta, **non dà punteggi né classifiche**. Accuratezza e completezza sono tutto: un valore sbagliato o mancante è una responsabilità reale verso il cliente.

## ⚠️ REGOLA D'ORO — MAI REGRESSIONI
Il vincolo più importante del progetto. Ogni modifica deve essere **additiva o dimostrabilmente sicura**. "Non perdere mai qualità rispetto al baseline precedente" è sacro. In passato una regola troppo aggressiva ("enumera TUTTE le garanzie") ha destabilizzato l'output (varianza, troncamento) ed è stata annullata. Preferire sempre:
- modifiche additive (aggiungono, non sovrascrivono);
- kill-switch via env var;
- passaggi separati che, se falliscono, lasciano intatto il baseline (try/except → fallback);
- test golden verdi prima e dopo.
Non si testa in produzione senza rete di sicurezza. Se una modifica tocca il prompt baseline (prima passata), è la strada rischiosa: valutare bene e renderla reversibile in un commit.

## Stack & deploy
- **Backend**: Python + FastAPI, tutto in `backend/main.py` (~4.5k righe). Deploy su **Railway** (git push → auto-deploy).
- **Frontend**: HTML+JS vanilla, `frontend/index.html` (single page). Deploy su **Vercel** (`polizza-facile.vercel.app`).
- **Storage**: **Qdrant** (usato come key-value via payload dei point). Persistente.
- **LLM**: Anthropic Claude, 3 tier (env-override):
  - `MODEL_VISION=claude-opus-4-6` — estrazione PDF vision (il cuore).
  - `MODEL_TEXT=claude-sonnet-4-6` — raffinamento testo/match.
  - `MODEL_FAST=claude-haiku-4-5` — detect tipo, summary, raccomandazioni.
  - Tutte le chiamate passano da `call_claude(**kwargs)` (wrapper con retry).
- **Repo**: github.com/PierNeo/polizza-facile

## Come testare (fallo sempre)
```bash
cd backend
python3 -m py_compile main.py            # sintassi
python3 -m pytest tests/test_pure.py -q  # unit test funzioni pure
python3 tests/regression_extraction.py   # golden (14 fixture in tests/regression/)
```
I golden (`tests/regression/*.expected.json`) fissano valori noti-corretti: un cambio al prompt non deve farli regredire. Path-resolver supporta `sezione:<id>`, `sezione:<id>.campo`, `garanzie_detail.x.gz.y.sub`; check: `present/contains/state/absent`.

## Pipeline di estrazione (il cuore — dove guardare)
Flusso per un CGA PDF:
1. **Detect tipo** (Haiku) → ramo: `Casa`, `Aziendale`, `Infortuni`, `RC Auto`. (Vita/Salute esclusi per ora.) Seleziona schema e regole di dominio.
2. **Chunking** → il PDF diviso in blocchi di pagine, inviati a Claude Opus come **document block nativo** (base64 PDF); la vision la fa Claude.
3. **Estrazione via `tool_use`** contro `_sezione_schema(tipo)` → dati tipizzati. `max_tokens=16384` con **retry anti-troncamento** fino a 32000 se il JSON viene tagliato.
4. **Merge / normalize** → `_merge_sezioni`, `_normalize_sezioni`.
5. **Secondo passaggio completezza** `_extract_gaps_sezioni` — passata Opus **additiva**. Riceve la lista già estratta + una **checklist fissa per ramo** (`_CHECKLIST_RAMO`: es. Aziendale = eventi atmosferici, allagamento, fenomeno elettrico, atti vandalici, furto, catastrofi…) e verifica ogni voce nel CGA, aggiungendo le coperte mancanti **senza toccare il baseline** (dedup per nome normalizzato). Gate: `_GAP_FILL_TIPI`. Kill-switch: `GAP_FILL_DISABLED=1`.
6. **Cache risultato** in memoria per hash del PDF. Bypass: `EXTRACTION_CACHE_DISABLED=1` (per test di ripetibilità).

**Prompt caching** Anthropic (`cache_control: ephemeral`) sul document block → il secondo passaggio rilegge il PDF a costo ridotto (~+15-25%).

Funzioni chiave: `_build_sezioni_prompt`, `_sezione_schema`, `_extract_sezioni_chunk`, `_merge_sezioni`, `_normalize_sezioni`, `_refine_sezioni`, `_extract_gaps_sezioni`, `_CHECKLIST_RAMO`.
Endpoint estrazione: `POST /api/extract-sezioni` (sync) e `/api/extract-sezioni-stream` (SSE, usato dal frontend).

## Due modelli dati (per ramo)
- **`sezioni[]`** (Aziendale/Salute/Infortuni/RC Auto): lista di sezioni-garanzia con `nome, id, inclusa, opzionale, massimale, massimale_num, scoperto, franchigia, formule` (quali soluzioni la includono) e `gz` (sotto-garanzie annidate).
- **`garanzie_detail`** (Casa): struttura annidata con gruppi (incendio, furto, rc, catastrofi…) ognuno con `gz` a chiavi model-generate.
Il frontend rende entrambi nella stessa tabella 3 colonne (Limite/Scoperto/Franchigia), celle multi-alternativa una-per-riga.

## Libreria CGA (catalogo)
- `backend/cga_catalog.json` — 75 prodotti (Casa 29, Aziendale 13, Infortuni 22, RC Auto 11). Ognuno: `id, compagnia, prodotto, tipo, url, url_type, extracted`.
- **Persistenza**: `_load_catalog` fa merge repo→persistente; i dati estratti si salvano in **Qdrant** (`_q_set_library`) → una volta popolati **restano per sempre**.
- **Sync** (`_sync_entry` via `/api/library/sync`, `/api/library/sync-stream`): scarica il PDF dall'URL, hash MD5, se cambiato ri-estrae (ora **con il secondo passaggio checklist**, appena allineato), salva in Qdrant. Incrementale: hash uguale → skip (costo zero). `cron-sync` notturno disattivato di default (`ENABLE_CRON_SYNC`).
- I prodotti `url_type=upload` (senza URL) vanno caricati a mano (`/api/library/upload-pdf`).

## Env vars importanti (Railway)
- `ANTHROPIC_API_KEY`, `QDRANT_URL`/`QDRANT_API_KEY`
- `SESSION_SECRET` — **da impostare fisso** (se assente, token invalidati a ogni redeploy → errore "Non autenticato")
- `GAP_FILL_DISABLED`, `EXTRACTION_CACHE_DISABLED`, `ENABLE_CRON_SYNC` — flag operativi
- (futuro) `GEMINI_API_KEY` — per il secondo parere Gemini (vedi sotto)

## Lavori in sospeso (roadmap attuale)
1. **Multi-PDF / prodotti modulari**: alcuni prodotti (es. Allianz Ultra Impresa = Fabbricato+Contenuto+Furto+RC…) sono spezzati in più PDF. Oggi il catalogo tiene un solo URL/prodotto. **Da fare**: campo `urls: [...]` nel catalogo + `_sync_entry` che scarica e **unisce** i moduli prima di estrarre.
2. **Verifica "CGA corretto" nella sync**: la sync scarica ciecamente dall'URL. **Da fare**: controllo leggero che il nome prodotto compaia nel testo scaricato (ed evitare di scaricare un DIP-riassunto invece del fascicolo completo) → altrimenti flag "da verificare".
3. **Verifica manuale link Aziendale nuovi**: i link Generali/AXA/Groupama aggiunti al catalogo vanno controllati (prodotto giusto, edizione attuale, fascicolo completo).
4. **Secondo parere Gemini** (in attesa di API key): cross-check di completezza **on-demand e isolato** — endpoint separato `/api/second-opinion`, mai auto-merge, fallback graceful, flag `GEMINI_CROSSCHECK_ENABLED`. Esperimento già fatto: anche Gemini Flash trova gap reali (soprattutto sotto-limiti RC estratti come semplice "Inclusa"). Vale come pannello consultivo, non autoritativo.
5. **Chat AI**: `/api/chat` + indicizzazione fulltext CGA (`_cga_store_text`, `_cga_retrieve`) con system prompt anti-allucinazione (solo da estratti, cita pagina, "Non risulta nel CGA" se assente).

## Convenzioni
- Tutto il backend in un file (`main.py`). Se si modularizza, farlo con cautela e per seam chiari.
- Commit piccoli e descrittivi; il deploy è automatico su push → non rompere `main`.
- Prima di ogni push: `py_compile` + golden verdi.
- Le regole di dominio (nel prompt) sono conoscenza guadagnata sul campo verificando CGA reali: non rimuoverle senza motivo, aggiungere in modo mirato.

## Riferimenti utili nel workspace (fuori repo)
- `Ground Truth CGA - riferimento verifica.md` — valori chiave verificati a mano per prodotto (metro di paragone).
- `ARCHITECTURE.md` — overview in inglese per revisori esterni.
