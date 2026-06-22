#!/usr/bin/env python3
"""
Regression sulla QUALITÀ dell'estrazione — NON fa parte della suite automatica.

Chiama davvero l'API (Claude) tramite il backend in esecuzione: COSTA crediti e
impiega tempo. Va lanciato a mano quando si toccano i prompt di estrazione, per
accorgersi di regressioni (es. migliorare Unipol e peggiorare Generali).

COME FUNZIONA
  1. Cartella backend/tests/regression/ con coppie:
        <caso>.pdf            → il PDF della polizza
        <caso>.expected.json  → i valori attesi (vedi formato sotto)
  2. Avvia il backend (o puntalo a produzione) e crea un account.
  3. Lancia:
        BACKEND_URL=https://...railway.app PF_USER=carlo PF_PASS=... \
        python3 tests/regression_extraction.py

FORMATO <caso>.expected.json
  {
    "tipo": ["Casa", "Multirischio"],          // tipo accettato (lista o stringa)
    "checks": [
      {"desc":"RC 5M",          "path":"garanzie_detail.rc.mass",                 "contains":"5.000.000"},
      {"desc":"Furto preziosi", "path":"garanzie_detail.furto.gz.preziosi.sub",   "contains":"15.000"},
      {"desc":"Eventi atm opz", "path":"garanzie_detail.incendio.gz.eventi_atm",  "state":"optional"},
      {"desc":"RC assente",     "path":"garanzie_detail.rc",                       "absent":true},
      {"desc":"Tutela legale",  "path":"sezione:tutela_legale",                    "present":true}
    ]
  }

  PATH:
    - dotted nei dict:  garanzie_detail.furto.gz.preziosi.sub
    - sezione per id:   sezione:tutela_legale  (oppure sezione:tutela_legale.massimale)
  ASSERZIONI (una per check):
    - contains: <str>   → il valore (stringa) contiene la sottostringa (case-insensitive)
    - equals:   <any>   → uguaglianza esatta
    - present:  true    → il valore esiste e non è None
    - absent:   true    → il valore è assente o None (es. sezione in modulo separato)
    - state: included|optional|excluded|sa  → stato di una sotto-garanzia garanzie_detail
        included = inclusa (oggetto senza opt); optional = {"opt":true};
        excluded = null;  sa = inclusa senza limiti (oggetto vuoto/sub null)
"""
import os, sys, json, base64, glob, ssl
import urllib.request, urllib.error  # solo libreria standard: nessuna dipendenza da installare

# Alcune installazioni Python su macOS (python.org) non hanno i certificati di sistema
# e danno "CERTIFICATE_VERIFY_FAILED". Questo è uno script di diagnostica verso il TUO
# backend noto, quindi disabilitiamo la verifica SSL solo qui (non in produzione).
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
PF_USER = os.getenv("PF_USER", "")
PF_PASS = os.getenv("PF_PASS", "")
CASES_DIR = os.path.join(os.path.dirname(__file__), "regression")

_MISSING = object()


def _post_json(url: str, payload: dict, headers: dict = None, timeout: int = 600) -> dict:
    data = json.dumps(payload).encode("utf-8")
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "ignore")
        raise RuntimeError(f"HTTP {e.code}: {body[:200]}")


def _login() -> str:
    return _post_json(f"{BACKEND_URL}/api/auth/login",
                      {"username": PF_USER, "password": PF_PASS}, timeout=30)["token"]


def _extract(token: str, pdf_path: str) -> dict:
    pdf_b64 = base64.b64encode(open(pdf_path, "rb").read()).decode()
    return _post_json(
        f"{BACKEND_URL}/api/extract-sezioni",
        {"pdf_base64": pdf_b64, "filename": os.path.basename(pdf_path)},
        headers={"Authorization": f"Bearer {token}"},
        timeout=600,
    )


def _resolve(result: dict, path: str):
    """Risolve un path nel JSON estratto. Ritorna _MISSING se non trovato."""
    # sezione per id
    if path.startswith("sezione:"):
        rest = path[len("sezione:"):]
        sid, _, field = rest.partition(".")
        sez = next((s for s in (result.get("sezioni") or []) if s.get("id") == sid), None)
        if sez is None:
            return _MISSING
        return sez if not field else sez.get(field, _MISSING)
    # dotted nei dict
    cur = result
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _check_state(val, want: str) -> bool:
    # val è il valore di una sotto-garanzia in garanzie_detail.<sez>.gz.<id>
    if want == "excluded":
        return val is None
    if val is _MISSING:
        return False
    if want == "optional":
        return isinstance(val, dict) and bool(val.get("opt"))
    if want == "included":
        return isinstance(val, dict) and not val.get("opt")
    if want == "sa":
        return isinstance(val, dict) and not val.get("opt") and not val.get("sub")
    return False


def _check_one(result: dict, chk: dict) -> str:
    """Ritorna '' se ok, altrimenti una descrizione dell'errore."""
    path = chk["path"]
    # state ha bisogno del valore grezzo (anche None)
    if "state" in chk:
        # per 'excluded' il path punta alla chiave che può essere null/assente
        raw = _resolve(result, path)
        val = None if raw is _MISSING and chk["state"] == "excluded" else raw
        ok = _check_state(None if val is _MISSING else val, chk["state"])
        return "" if ok else f"stato atteso '{chk['state']}', trovato {('<assente>' if raw is _MISSING else json.dumps(raw, ensure_ascii=False))}"
    val = _resolve(result, path)
    if chk.get("absent"):
        return "" if (val is _MISSING or val is None) else f"atteso assente, trovato {json.dumps(val, ensure_ascii=False)[:80]}"
    if chk.get("present"):
        return "" if (val is not _MISSING and val is not None) else "atteso presente, ma assente"
    if "contains" in chk:
        if val is _MISSING or val is None:
            return f"atteso contenente '{chk['contains']}', ma assente"
        return "" if chk["contains"].lower() in str(val).lower() else f"atteso contenente '{chk['contains']}', trovato '{val}'"
    if "equals" in chk:
        return "" if val == chk["equals"] else f"atteso = {chk['equals']!r}, trovato {val!r}"
    return "check senza asserzione valida"


def _check_case(result: dict, expected: dict) -> list:
    diffs = []
    if "tipo" in expected:
        ammessi = expected["tipo"] if isinstance(expected["tipo"], list) else [expected["tipo"]]
        if result.get("tipo") not in ammessi:
            diffs.append(f"tipo: atteso uno di {ammessi}, trovato {result.get('tipo')!r}")
    for chk in expected.get("checks", []):
        err = _check_one(result, chk)
        if err:
            diffs.append(f"{chk.get('desc', chk.get('path'))}: {err}")
    return diffs


def main() -> int:
    if not PF_USER or not PF_PASS:
        print("Imposta PF_USER e PF_PASS (e BACKEND_URL).")
        return 2
    cases = sorted(glob.glob(os.path.join(CASES_DIR, "*.expected.json")))
    if not cases:
        print(f"Nessun caso in {CASES_DIR}.")
        return 0
    token = _login()
    total = 0
    for exp_path in cases:
        case = os.path.basename(exp_path).replace(".expected.json", "")
        pdf_path = os.path.join(CASES_DIR, f"{case}.pdf")
        if not os.path.exists(pdf_path):
            print(f"[{case}] SKIP — manca {case}.pdf (mettilo nella cartella regression/)")
            continue
        expected = json.load(open(exp_path, encoding="utf-8"))
        print(f"[{case}] estrazione…")
        try:
            result = _extract(token, pdf_path)
        except Exception as e:
            print(f"[{case}] ERRORE estrazione: {e}")
            total += 1
            continue
        diffs = _check_case(result, expected)
        if diffs:
            total += len(diffs)
            print(f"[{case}] ❌ {len(diffs)} differenze:")
            for d in diffs:
                print(f"    - {d}")
        else:
            print(f"[{case}] ✅ ok ({len(expected.get('checks', []))} check superati)")
    print(f"\nTotale differenze: {total}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
