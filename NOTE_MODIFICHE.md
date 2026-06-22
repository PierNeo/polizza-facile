# Polizza Facile — Note di progetto

Riepilogo di tutto il lavoro fatto (sicurezza, account, qualità estrazione, output,
regressione) e di come si usa. Regole rispettate: i `git commit` li fai tu; nessuna
riduzione di qualità voluta.

---

## 1. Sicurezza e account

- **Login con account per assicuratore.** Niente più chiave statica nel frontend
  (era pubblica). Si entra con username+password → token di sessione firmato (HMAC),
  password con hash PBKDF2. Account attuali: `carlo`, `leonardo`, `nicolo`.
- **Dati privati per account, libreria CGA condivisa.** Clienti / polizze /
  configurazione sono separati per utente; il catalogo CGA è in comune.
- **CORS** chiuso al dominio Vercel. **Anti-brute-force** sul login (20 tentativi/15 min).
- Rimosse le vecchie interfacce `backend/index.html` e `backend/nicolo.html` (si usa
  solo l'app su Vercel; la root del backend mostra solo "API attiva").

### Variabili d'ambiente su Railway
| Variabile | A cosa serve |
|---|---|
| `SESSION_SECRET` | Firma i token. Lungo e casuale (`openssl rand -hex 32`). **Non cambiarlo** dopo. |
| `ADMIN_KEY` | Crea/aggiorna account via API. |
| `ADMIN_USERNAME` + `ADMIN_PASSWORD` | Account creato al primo avvio. |
| `DATA_OWNER_USERNAME` | Una-tantum: assegna i dati esistenti al tuo account. |
| `ALLOWED_ORIGINS` | Dominio Vercel **senza `/` finale**. |
| `ANTHROPIC_API_KEY`, `QDRANT_URL`, `QDRANT_API_KEY` | già impostate. |
| `MODEL_VISION` | modello estrazione (attuale: `claude-opus-4-8`). |
| Opzionali | `SESSION_TTL_HOURS`, `MODEL_TEXT`, `MODEL_FAST`, `MAX_PDF_BYTES`, `MAX_PDF_PAGES`, `ENABLE_CRON_SYNC`. |

### Creare / cambiare un account
```bash
curl -X POST https://polizza-facile-production.up.railway.app/api/auth/create-user \
  -H "Content-Type: application/json" \
  -d '{"username":"nome","password":"passwordLunga","admin_key":"<ADMIN_KEY>"}'
```
(Stesso comando con lo stesso username = cambia la password. Min 8 caratteri.)

---

## 2. Robustezza backend

- **Retry automatico** su tutte le chiamate AI (errore 529).
- **Modelli configurabili** da env (nessuna stringa nel codice); lo `.strip()` evita
  errori da spazi.
- **`cryptography`** aggiunta alle dipendenze: i PDF di polizza **cifrati (AES)** ora
  si leggono (prima fallivano).
- **Cap PDF** generoso e "best-effort" (40 MB / 400 pagine): non blocca le polizze
  lunghe, solo gli upload abnormi.
- **Salvataggi Qdrant** atomici e con errori onesti (niente più falso "ok").
- **Sync notturno DISATTIVATO di default** (`/api/cron-sync` non fa nulla senza
  `ENABLE_CRON_SYNC=1`) → nessun costo automatico. Le polizze si aggiornano a mano.
- **Messaggi di errore chiari**: se l'AI non risponde l'app dice *"Crediti AI
  esauriti"* / *"Servizio AI sovraccarico"* invece del generico "nessun dato".

---

## 3. Libreria CGA (catalogo condiviso)

- Il frontend legge il catalogo **dal backend** (fonte unica): le due copie non si
  disallineano più. Si modifica solo `backend/cga_catalog.json`.
- Ogni voce ha il pulsante **"Carica PDF / Ricarica PDF"**: carichi a mano il PDF e
  l'estrazione gira sul backend, salvando nella libreria condivisa.
- Per i **prodotti modulari** (es. Allianz, Unipol) i moduli vanno **uniti in un solo
  PDF** prima di caricarli, altrimenti le sezioni in moduli separati risultano
  "non in doc.".

---

## 4. Output dell'analisi / confronto

- **Strumento di analisi**, non solo confronto: funziona anche su **una sola polizza**
  (il pulsante diventa "Analizza polizza").
- **Vista sintetica** = griglia a **3 colonne per polizza: Limite · Scoperto ·
  Franchigia** (colori distinti). **Vista dettaglio** = stesse sezioni con le note
  complete.
- **"S.A."** dove non c'è un limite specifico (coperto fino alla somma assicurata);
  niente più spunte verdi; niente più valori d'esempio (mock rimossi).
- Distinzione chiara: **"Esclusa"** (esclusa dal contratto) vs **"non in doc."**
  (sezione assente, es. modulo separato) vs **"◆ opz."** (opzionale a pagamento).
- Le coperture **marginali/di nicchia** vanno in fondo; le **esclusioni** in fondo.
- Indicatore per polizza: **"⚠ N sezioni non documentate"** (con elenco al passaggio
  del mouse), utile a capire quando manca un modulo.

---

## 5. Qualità estrazione (prompt)

Regole generali (valgono per tutte le compagnie, non patch):
- **Limite ≠ sotto-cap**: un tetto su voci particolari (es. lastre, colonnine) NON è
  il limite della garanzia → se la base copre fino alla S.A., Limite = "S.A.".
- **Opzionale solo con frase esplicita** ("supplementare / a pagamento / se
  acquistata"); altrimenti la garanzia è inclusa.
- **Esclusa vs assente**: si omette ciò che non è nel documento; "esclusa" solo se il
  testo lo esclude esplicitamente.
- **Deep-merge** dei dettagli tra i blocchi di un PDF lungo (prima si perdevano
  sezioni su documenti multi-pagina).

---

## 6. Test e regressione

### Test automatici (gratis, locali)
```bash
cd backend
pytest -q     # ~22 test sulle funzioni pure (auth, merge, limiti PDF, ...)
```

### Regressione qualità estrazione (a pagamento — chiama l'AI)
"Compito con le risposte corrette" su 6 polizze note (Tuttocasa, Unipol Casa, AXA,
Generali, Helvetia, Unipol Infortuni), per validare che una modifica ai prompt
migliori senza rompere. I valori attesi sono in `backend/tests/regression/*.expected.json`
(i PDF restano locali, esclusi dal repo).

```bash
cd backend
export BACKEND_URL=https://polizza-facile-production.up.railway.app
export PF_USER=carlo
export PF_PASS=<password>
# Sottoinsieme (spendi meno mentre iteri ~ pochi $):
python3 tests/regression_extraction.py unipol-unica-casa
# Tutte e 6 (prima di un rilascio ~ $10-15):
python3 tests/regression_extraction.py
```
Stampa ✅/❌ per ogni controllo. Da rilanciare **dopo ogni modifica ai prompt**
(e dopo il deploy, così la cache è fresca).

Cosa dà: alta confidenza sui ~29 controlli delle 6 polizze e che le modifiche non
regrediscano. Cosa NON dà: copertura totale di ogni voce/ogni compagnia → resta la
regola d'oro *"verificare prima di fare una proposta"*.

---

## 7. Punti aperti / prossimi passi

- **Batch API per la regressione** (−50% di costo): da fare quando serve, va testata
  sul vivo (con crediti).
- **Documenti modulari completi** (es. Unipol RC + Tutela Legale uniti) per eliminare
  i "non in doc.".
- Allargare i golden (più ancore per polizza) e curare il dizionario sinonimi
  Infortuni man mano che si testano nuove polizze.
- Cambiare `ADMIN_KEY` / password rese visibili durante i test.
