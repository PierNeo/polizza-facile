# Polizza Facile — Modifiche sessione (sicurezza, robustezza, account)

> Regole rispettate: nessun `git commit` eseguito (li fai tu dal Terminal); nessuna
> riduzione di qualità (i prompt e i modelli non sono stati cambiati — solo resi
> configurabili).

## Cosa è cambiato (in breve)

1. **Login con account per assicuratore.** Niente più chiave statica nel frontend
   (era pubblica e aggirabile). Ora si entra con username+password e un token di
   sessione. Account previsti: tu, Leonardo, Nicolò.
2. **Dati privati per account, libreria CGA condivisa.** Clienti, polizze e
   configurazione sono separati per utente; il catalogo CGA resta in comune.
3. **CORS chiuso** al dominio del frontend (prima era aperto a tutti con `*`).
4. **Cap PDF generoso** (40 MB / 400 pagine, configurabili) — le polizze lunghe
   passano comunque; serve solo a fermare upload abnormi.
5. **Retry su 529** ora su *tutte* le chiamate Claude (prima solo metà).
6. **Modelli centralizzati** in costanti/env (vedi nota su `claude-opus-4-6`).
7. **Salvataggi onesti**: se Qdrant non salva, l'API risponde errore (prima diceva
   sempre "ok").
8. **Anti-brute-force** sul login (20 tentativi / 15 min per IP).
9. **Test** automatici (`backend/tests/`) + script di regression estrazione.

## Variabili d'ambiente da impostare su Railway

Obbligatorie/consigliate:

| Variabile | A cosa serve |
|---|---|
| `SESSION_SECRET` | Firma i token di login. Valore lungo e casuale: `openssl rand -hex 32`. **Non cambiarlo** dopo (invaliderebbe i login). |
| `ADMIN_KEY` | Permette di creare account via API. Valore segreto a tua scelta. |
| `ADMIN_USERNAME` + `ADMIN_PASSWORD` | Crea il tuo account al primo avvio (così puoi entrare subito). |
| `DATA_OWNER_USERNAME` | Una-tantum: assegna i dati già esistenti al tuo account (metti il tuo username, es. `carlo`). |
| `ALLOWED_ORIGINS` | Dominio del frontend Vercel (es. `https://...vercel.app`). |

Già esistenti (lasciale come sono): `ANTHROPIC_API_KEY`, `QDRANT_URL`,
`QDRANT_API_KEY`, `CRON_API_KEY`.

Opzionali: `SESSION_TTL_HOURS` (default 168 = 7 giorni), `MODEL_VISION/MODEL_TEXT/
MODEL_FAST`, `MAX_PDF_BYTES`, `MAX_PDF_PAGES`.

## Come creare gli account (dopo il deploy)

1. Imposta `ADMIN_USERNAME`/`ADMIN_PASSWORD` (il tuo) e `ADMIN_KEY` su Railway → riavvia.
   Ora puoi fare login con il tuo account.
2. Crea Leonardo e Nicolò con una chiamata (dal tuo Terminal):

```bash
curl -X POST https://<tuo-backend>.railway.app/api/auth/create-user \
  -H "Content-Type: application/json" \
  -d '{"username":"leonardo","password":"unaPasswordLunga","admin_key":"<ADMIN_KEY>"}'

curl -X POST https://<tuo-backend>.railway.app/api/auth/create-user \
  -H "Content-Type: application/json" \
  -d '{"username":"nicolo","password":"unaPasswordLunga","admin_key":"<ADMIN_KEY>"}'
```

Password minimo 8 caratteri. Per cambiare una password, richiama lo stesso endpoint
con lo stesso username.

## Push (quando hai verificato)

Sono stati anche **rimossi** `backend/index.html` e `backend/nicolo.html` (vecchie
interfacce non più usate): si usa solo l'app su Vercel. La rotta `/` del backend ora
mostra solo una paginetta "API attiva", e `/nicolo` non esiste più. Per includere
anche le cancellazioni nel commit, usa `git add -A`:

```bash
cd ~/Desktop/Claude\ Workspace/polizza-facile
git add -A
git commit -m "feat: auth account per assicuratore + hardening sicurezza/robustezza + test; rimosse interfacce backend legacy"
git push
```

## Punti che restano aperti (tua decisione)

- ~~`backend/index.html` e `backend/nicolo.html`~~ → **rimossi** (usi solo Vercel).
- **`claude-opus-4-6`**: verifica che sia ancora un modello attivo. Se vuoi un Opus
  più recente, basta impostare `MODEL_VISION=claude-opus-4-8` su Railway — nessuna
  modifica al codice.
- **`/api/library/check-urls`**: ha un controllo a chiave debole e separato (env
  `API_KEY`, probabilmente non impostata). È solo diagnostico/sola-lettura; se vuoi
  lo lego ad `ADMIN_KEY`.
- **Estrazione Infortuni / `garanzie_detail`**: invariata. Quando ci lavori, usa lo
  script `backend/tests/regression_extraction.py` per non regredire su Casa.

## Test

```bash
cd backend
pip install pytest --break-system-packages
pytest -q            # 19 test, gratis, ~1s
```
