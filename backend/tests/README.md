# Test — Polizza Facile backend

Due livelli, con scopi diversi.

## 1. `test_pure.py` — automatico, gratis, veloce

Test deterministici sulle funzioni pure (auth/hashing/token, isolamento dati
per-utente, limiti PDF, cache key, indice sinonimi, scoring chunk). Non chiamano
la rete né l'API Anthropic. Da eseguire a ogni modifica.

```bash
cd backend
pip install pytest --break-system-packages   # solo la prima volta
pytest -q
```

Non serve una vera `ANTHROPIC_API_KEY`: il file ne imposta una fittizia prima di
importare `main`.

## 2. `regression_extraction.py` — manuale, a pagamento

Verifica la **qualità dell'estrazione** chiamando davvero Claude tramite il
backend. Costa crediti: lanciarlo a mano quando si toccano i prompt (es. dopo aver
migliorato gli Infortuni, per controllare di non aver rotto Casa).

1. Crea `backend/tests/regression/` con coppie `<caso>.pdf` + `<caso>.expected.json`.
2. Avvia il backend (o punta a produzione) e crea un account.
3. Esegui:

```bash
BACKEND_URL=https://<tuo>.railway.app PF_USER=carlo PF_PASS=... \
  python3 tests/regression_extraction.py
```

Confronta solo i campi elencati in `expected.json` (massimali, scoperti, frammenti
di note). Exit code ≠ 0 se trova differenze.
