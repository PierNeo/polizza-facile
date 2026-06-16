"""
Test deterministici sulle funzioni pure di main.py.
Non chiamano l'API Anthropic né la rete: sono gratis e veloci, pensati per
girare a ogni modifica (es. quando si ritoccano i prompt o lo storage).

Esecuzione:
    cd backend
    pip install pytest --break-system-packages   # se non già presente
    ANTHROPIC_API_KEY=dummy pytest -q
"""
import os
import io
import importlib

import pytest

# main.py crea il client Anthropic a import-time: gli serve una chiave (non viene
# usata la rete in questi test). Impostiamo un valore fittizio prima dell'import.
os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-key-for-tests")

from pypdf import PdfWriter
from fastapi import HTTPException

main = importlib.import_module("main")


# ── AUTENTICAZIONE: PASSWORD ──────────────────────────────────────────────────

def test_password_hash_e_verifica():
    h = main._hash_password("CorrectHorse9")
    assert h.startswith("pbkdf2_sha256$")
    assert main._verify_password("CorrectHorse9", h) is True
    assert main._verify_password("sbagliata", h) is False

def test_password_hash_e_salato():
    # Due hash della stessa password devono differire (salt casuale)
    assert main._hash_password("stessa") != main._hash_password("stessa")

def test_verify_password_input_malformato():
    assert main._verify_password("x", "non-un-hash-valido") is False
    assert main._verify_password("x", "") is False


# ── AUTENTICAZIONE: TOKEN DI SESSIONE ─────────────────────────────────────────

def test_token_valido_round_trip():
    t = main._make_token("mario")
    assert main._verify_token(t) == "mario"

def test_token_manomesso_rifiutato():
    t = main._make_token("mario")
    assert main._verify_token(t + "x") is None          # firma alterata
    body, sig = t.split(".")
    assert main._verify_token(f"{body}.{sig}.extra") is None

def test_token_scaduto_rifiutato():
    t = main._make_token("mario", ttl=-10)               # già scaduto
    assert main._verify_token(t) is None

def test_token_vuoto_o_spazzatura():
    assert main._verify_token("") is None
    assert main._verify_token("spazzatura") is None
    assert main._verify_token(None) is None

def test_token_di_altro_segreto_rifiutato(monkeypatch):
    t = main._make_token("mario")
    monkeypatch.setattr(main, "SESSION_SECRET", "un-altro-segreto")
    assert main._verify_token(t) is None


# ── PID PER-UTENTE (ISOLAMENTO DATI) ──────────────────────────────────────────

def test_user_pid_deterministico():
    assert main._user_pid("clients", "mario") == main._user_pid("clients", "mario")

def test_user_pid_diverso_per_utente_e_per_tipo():
    assert main._user_pid("clients", "mario") != main._user_pid("clients", "luigi")
    assert main._user_pid("clients", "mario") != main._user_pid("polizze", "mario")

def test_user_pid_e_un_uuid():
    import uuid
    uuid.UUID(main._user_pid("config", "mario"))  # non solleva se valido


# ── CACHE KEY ─────────────────────────────────────────────────────────────────

def test_cache_key_stabile_e_sensibile():
    a = main._cache_key("contenuto polizza " * 100)
    assert a == main._cache_key("contenuto polizza " * 100)
    assert a != main._cache_key("contenuto diverso " * 100)


# ── LIMITI PDF ────────────────────────────────────────────────────────────────

def _pdf_di_pagine(n: int) -> bytes:
    w = PdfWriter()
    for _ in range(n):
        w.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()

def test_check_pdf_limits_ok():
    main._check_pdf_limits(_pdf_di_pagine(3))  # non solleva

def test_check_pdf_limits_troppo_grande(monkeypatch):
    monkeypatch.setattr(main, "MAX_PDF_BYTES", 100)
    with pytest.raises(HTTPException) as e:
        main._check_pdf_limits(_pdf_di_pagine(2))
    assert e.value.status_code == 413

def test_check_pdf_limits_troppe_pagine(monkeypatch):
    monkeypatch.setattr(main, "MAX_PDF_PAGES", 1)
    with pytest.raises(HTTPException) as e:
        main._check_pdf_limits(_pdf_di_pagine(5))
    assert e.value.status_code == 413

def test_check_pdf_limits_corrotto_non_blocca():
    # Best-effort: un PDF illeggibile ma sotto il cap MB NON deve bloccare l'estrazione
    # (Claude lo legge comunque a vista; il conteggio pagine è solo un guardrail).
    main._check_pdf_limits(b"questo non e un pdf valido" * 10)  # non solleva

def test_check_pdf_limits_corrotto_ma_enorme(monkeypatch):
    # Se però supera il cap MB, deve bloccare anche se illeggibile
    monkeypatch.setattr(main, "MAX_PDF_BYTES", 50)
    with pytest.raises(HTTPException) as e:
        main._check_pdf_limits(b"spazzatura" * 100)
    assert e.value.status_code == 413


# ── INDICE SINONIMI SEZIONI ───────────────────────────────────────────────────

def test_build_synonym_index():
    mapping = {
        "incendio": {"nome_standard": "Incendio", "sinonimi": ["Fuoco", "Fiamme"]},
    }
    idx = main._build_synonym_index(mapping)
    assert idx["incendio"] == "incendio"   # nome standard, lowercase
    assert idx["fuoco"] == "incendio"      # sinonimo, lowercase
    assert idx["fiamme"] == "incendio"


# ── SCORING CHUNK ─────────────────────────────────────────────────────────────

def test_score_chunk_vuoto_e_zero():
    assert main._score_chunk("") == 0

def test_score_chunk_premia_keyword_e_importi():
    basso = main._score_chunk("testo qualunque senza nulla di rilevante")
    alto = main._score_chunk("Massimale e somma assicurata: €500.000 per sinistro, franchigia €250")
    assert alto > basso
