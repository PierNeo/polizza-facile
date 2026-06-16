# Qualità estrazione — analisi e roadmap (Casa + Infortuni)

Review della pipeline a sezioni (v3): `_detect_tipo_pdf` → `_extract_sezioni_chunk` →
`_merge_sezioni` → `_normalize_sezioni` → `_refine_sezioni`, più il comparatore frontend.

---

## Parte A — Problemi trovati (per gravità)

### 1. [ALTO] La libreria CGA è estratta SENZA il passaggio di raffinamento
`_sync_entry` (il cron che popola il catalogo) fa `extract → merge → normalize` ma
**non** chiama `_refine_sezioni`. Gli endpoint interattivi (`/api/extract-sezioni`)
invece lo chiamano. Conseguenza: **i dati del catalogo — quelli su cui si basano
TUTTI i confronti — sono sistematicamente meno completi** (mancano franchigie,
scoperti e sublimiti che il refine recupererebbe) rispetto a un'estrazione fresca.
Quando l'assicuratore confronta la polizza del cliente (estratta col refine) con
quelle in libreria (senza refine), queste ultime sembrano più scarne del vero.
→ **Fix**: chiamare `_refine_sezioni` anche dentro `_sync_entry`. È la singola
correzione col maggior impatto sulla qualità percepita.

### 2. [ALTO] Infortuni non ha estrazione strutturata dei sotto-limiti
`garanzie_detail` (i campi sub/scoperto/franchigia per ogni sotto-garanzia) è
definito **solo per Casa** (`_sezione_schema`: `if tipo_polizza == "Casa"`). Anche
il comparatore mostra le "chip" dettagliate solo per Casa (`buildTableGaranzieCasa`,
attiva solo se `isCasa`); Infortuni usa la tabella generica. Risultato: per Infortuni
il confronto è **grossolano** e i dettagli finiscono in testo libero (`note`,
`sublimiti`), non comparabili cella per cella. È il gap principale per un prodotto
Infortuni "finito".

### 3. [MEDIO-ALTO] Dati "mock" (di esempio) nel comparatore Casa
Se le polizze confrontate non hanno `garanzie_detail`, il comparatore mostra numeri
finti di esempio (`_MOCK_GARANZIE_CASA`) con badge "⚠ Struttura di esempio", e in
singole celle può usare un massimale mock come fallback. **Rischio di fiducia**: un
assicuratore potrebbe leggere numeri di esempio come reali. Da rimuovere appena
l'estrazione popola `garanzie_detail`, sostituendoli con "dato non disponibile".

### 4. [MEDIO] Il merge multi-chunk perde dati su `garanzie_detail`
`_merge_sezioni` per `garanzie_detail` prende **un solo chunk** (`best_gd = max(...)`)
invece di fondere i chunk. Per CGA Casa lunghe (>60 pagine = 2+ chunk) i dettagli di
sezioni che stanno in chunk diversi vengono persi. Le CGA brevi (1 chunk, la
maggioranza) non sono toccate, ma è un bug latente.
→ **Fix**: deep-merge per sezione/`gz`, non "prendi il migliore".

### 5. [MEDIO] Il refine cerca solo nel primo chunk
`_refine_sezioni(result, chunks[0][0], ...)` usa **solo il primo chunk** del PDF: i
valori oltre le prime 60 pagine non vengono mai recuperati. Inoltre il refine
aggiorna solo i campi testuali delle `sezioni`, **non** `garanzie_detail` (che quindi
non viene mai raffinato).

### 6. [MEDIO] Normalizzazione: i nomi non riconosciuti restano grezzi
In `_normalize_sezioni`, se il nome non è nel dizionario sinonimi ma il modello ha
messo un `id`, id/nome restano quelli (non standard) → **righe disallineate nel
confronto** (due polizze chiamano la stessa garanzia in modo diverso e finiscono su
righe separate). Dipende dalla copertura dei dizionari: Casa ne ha solo 7 sezioni,
Infortuni 22. La cura dei dizionari è un moltiplicatore di qualità diretto.

### 7. [BASSO-MEDIO] `_detect_tipo_pdf` fa fallback a "Casa"
Se Haiku sbaglia o fallisce, default "Casa". Un Infortuni mal rilevato verrebbe
estratto con schema/prompt Casa → estrazione scadente. Meglio fallback
"Multirischio" (carica entrambi i dizionari) o una doppia verifica.

### 8. [BASSO] Merge: nel ramo "vince l'esistente" integra solo campi fissi
`_merge_sezioni` reintegra solo `franchigia/scoperto/sublimiti/note/sotto_garanzie`;
un `massimale` o `inclusa` migliore da un chunk con score più basso va perso. Raro.

### 9. [BASSO] Nessun validatore deterministico post-estrazione
Il prompt chiede coerenza (es. `massimale_num` allineato al testo, scoperto col
minimo €) ma non c'è un controllo automatico. Un validatore a regole alzerebbe
l'affidabilità e darebbe un "punteggio di completezza" per polizza.

### 10. [BASSO] Chiave cache basata sui primi 2000 caratteri base64
`_cache_key` usa `pdf_base64[:2000] + len`. Due PDF con stesso inizio e stessa
lunghezza collidono (improbabile, ma possibile con template molto simili).

---

## Parte B — Roadmap verso un prodotto finito (Casa + Infortuni)

In ordine di valore/sforzo.

### Priorità 1 — Portare la libreria alla qualità delle estrazioni fresche
- **Aggiungere il refine al sync** (fix #1). Lift immediato su tutti i confronti.
- **Costruire il set di regressione** (lo script `backend/tests/regression_extraction.py`
  esiste già): 2-3 CGA Casa + 2-3 Infortuni reali con i valori attesi verificati a
  mano. Da lanciare prima di ogni modifica ai prompt. È la rete che permette di
  migliorare Infortuni senza rompere Casa.

### Priorità 2 — Portare Infortuni al livello di Casa
- **Definire `garanzie_detail` per Infortuni** (sub/scoperto/franchigia strutturati
  per sotto-garanzia: morte, IP base/grave, diarie, rimborso spese infortuni/malattia,
  rendite, ecc.), come già fatto per Casa.
- **Costruire `buildTableGaranzieInfortuni`** nel frontend (le chip) e attivarla per
  i confronti Infortuni.
- **Curare il dizionario sinonimi Infortuni** confrontando 2 polizze reali (come da
  handoff): allineare i nomi standard ai termini che usano davvero le compagnie.

### Priorità 3 — Onestà dell'output (fiducia = vendibilità)
- **Rimuovere i dati mock** dal comparatore (#3): celle senza dato → "non disponibile",
  mai numeri di esempio.
- **Validatore post-estrazione** (#9): regole deterministiche (massimale_num vs testo,
  scoperto con minimo €, flag su vuoti sospetti) + un **punteggio di completezza** per
  polizza, così l'assicuratore sa quanto fidarsi di ogni estrazione.

### Priorità 4 — Robustezza pipeline
- **Deep-merge di `garanzie_detail`** tra chunk (#4) e **refine su tutto il documento**
  o sulle pagine più dense (#5).
- **Fallback tipo migliore** (#7).

### Priorità 5 — Tracciabilità e correzione (ciò che rende il prodotto "vero")
- Mostrare per ogni valore estratto **la pagina/snippet di origine** (tracciabilità),
  così l'assicuratore può verificare in un clic.
- **UI di correzione**: l'assicuratore corregge un valore sbagliato e la correzione
  viene salvata (override). Questo chiude il cerchio della fiducia ed è ciò che
  distingue un demo da un prodotto.

---

## Suggerimento di sequenza pratica
1. Fix #1 (refine nel sync) — piccolo, alto impatto.
2. Set di regressione (2-3 Casa + 2-3 Infortuni).
3. `garanzie_detail` + tabella chip per Infortuni.
4. Rimozione mock + validatore/completezza.
5. Deep-merge e refine multi-chunk.
