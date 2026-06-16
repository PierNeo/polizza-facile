#!/usr/bin/env python3
"""
Regression sulla QUALITÀ dell'estrazione — NON fa parte della suite automatica.

A differenza di test_pure.py, questo script chiama davvero l'API (Claude) tramite
il backend in esecuzione: COSTA crediti e impiega tempo. Va lanciato a mano quando
si toccano i prompt di estrazione, per accorgersi di regressioni (es. migliorare
Casa e peggiorare Infortuni).

COME FUNZIONA
  1. Crea una cartella backend/tests/regression/ con coppie:
        <caso>.pdf            → il PDF della polizza
        <caso>.expected.json  → i valori attesi (vedi esempio sotto)
  2. Avvia il backend (o puntalo a quello in produzione) e crea un account.
  3. Lancia:
        BACKEND_URL=https://...railway.app \
        PF_USER=carlo PF_PASS=la-tua-password \
        python3 tests/regression_extraction.py

ESEMPIO di <caso>.expected.json (controlli mirati, non l'intero output):
  {
    "tipo": "Casa",
    "garanzie": {
      "Assistenza casa":   {"note_contiene": ["Alloggio max €300", "€250"]},
      "Responsabilità civile verso terzi": {"massimale_num": 5000000}
    }
  }

Per ogni caso confronta solo i campi indicati in expected.json: se un massimale o
uno scoperto cambia rispetto all'atteso, lo segnala. Exit code != 0 se ci sono
differenze (comodo per uno smoke test prima di un push).
"""
import os
import sys
import json
import base64
import glob

import httpx

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
PF_USER = os.getenv("PF_USER", "")
PF_PASS = os.getenv("PF_PASS", "")
CASES_DIR = os.path.join(os.path.dirname(__file__), "regression")


def _login() -> str:
    r = httpx.post(f"{BACKEND_URL}/api/auth/login",
                   json={"username": PF_USER, "password": PF_PASS}, timeout=30)
    r.raise_for_status()
    return r.json()["token"]


def _extract(token: str, pdf_path: str) -> dict:
    pdf_b64 = base64.b64encode(open(pdf_path, "rb").read()).decode()
    r = httpx.post(
        f"{BACKEND_URL}/api/extract-sezioni",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"pdf_base64": pdf_b64, "filename": os.path.basename(pdf_path)},
        timeout=600,
    )
    r.raise_for_status()
    return r.json()


def _find_garanzia(result: dict, nome: str):
    """Cerca una garanzia per nome in output a sezioni o a lista piatta."""
    for sez in (result.get("sezioni") or []):
        for g in (sez.get("garanzie_detail") or sez.get("garanzie") or []):
            if isinstance(g, dict) and g.get("nome") == nome:
                return g
    for g in (result.get("garanzie") or []):
        if isinstance(g, dict) and g.get("nome") == nome:
            return g
    return None


def _check_case(result: dict, expected: dict) -> list[str]:
    diffs = []
    if "tipo" in expected and result.get("tipo") != expected["tipo"]:
        diffs.append(f"tipo: atteso {expected['tipo']!r}, ottenuto {result.get('tipo')!r}")
    for nome, checks in (expected.get("garanzie") or {}).items():
        g = _find_garanzia(result, nome)
        if g is None:
            diffs.append(f"garanzia mancante: {nome!r}")
            continue
        if "massimale_num" in checks and g.get("massimale_num") != checks["massimale_num"]:
            diffs.append(f"{nome} · massimale_num: atteso {checks['massimale_num']}, ottenuto {g.get('massimale_num')}")
        for frammento in checks.get("note_contiene", []):
            note = (g.get("note") or "")
            if frammento.lower() not in note.lower():
                diffs.append(f"{nome} · note non contiene {frammento!r} (note={note[:120]!r})")
    return diffs


def main() -> int:
    if not PF_USER or not PF_PASS:
        print("Imposta PF_USER e PF_PASS (e BACKEND_URL).")
        return 2
    cases = sorted(glob.glob(os.path.join(CASES_DIR, "*.expected.json")))
    if not cases:
        print(f"Nessun caso in {CASES_DIR}. Crea coppie <caso>.pdf + <caso>.expected.json.")
        return 0
    token = _login()
    total_diffs = 0
    for exp_path in cases:
        case = os.path.basename(exp_path).replace(".expected.json", "")
        pdf_path = os.path.join(CASES_DIR, f"{case}.pdf")
        if not os.path.exists(pdf_path):
            print(f"[{case}] SKIP — manca {case}.pdf")
            continue
        expected = json.load(open(exp_path, encoding="utf-8"))
        print(f"[{case}] estrazione…")
        result = _extract(token, pdf_path)
        diffs = _check_case(result, expected)
        if diffs:
            total_diffs += len(diffs)
            print(f"[{case}] ❌ {len(diffs)} differenze:")
            for d in diffs:
                print(f"    - {d}")
        else:
            print(f"[{case}] ✅ ok")
    print(f"\nTotale differenze: {total_diffs}")
    return 1 if total_diffs else 0


if __name__ == "__main__":
    sys.exit(main())
