# main.py — Polizza Facile backend
import os
import re
import json
import asyncio
import logging
import base64
import io
import time
import threading
import hashlib
import hmac
import secrets
import uuid
from collections import defaultdict
import anthropic
import httpx
from pypdf import PdfReader, PdfWriter
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("polizza_facile")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Polizza Facile API", docs_url=None, redoc_url=None)

# ── SECURITY HEADERS ──────────────────────────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ── CORS ─────────────────────────────────────────────────────────────────────
# Se ALLOWED_ORIGINS non è impostato, permette tutto (default per sviluppo/SaaS)
_env_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
if _env_origins == "*" or not _env_origins:
    _origins = ["*"]
else:
    _origins = [o.strip() for o in _env_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
    expose_headers=["*"],
)

# Middleware aggiuntivo per forzare CORS headers su ogni risposta
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse

def _cors_allow_origin(request: StarletteRequest) -> str:
    """Ritorna l'Origin da autorizzare: '*' solo se l'allowlist è aperta,
    altrimenti l'Origin della richiesta se è in allowlist (echo), altrimenti il primo."""
    if _origins == ["*"]:
        return "*"
    origin = request.headers.get("origin", "")
    if origin and origin in _origins:
        return origin
    return _origins[0] if _origins else ""


class ForceCORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        if request.method == "OPTIONS":
            response = StarletteResponse(status_code=200)
        else:
            response = await call_next(request)
        allow_origin = _cors_allow_origin(request)
        if allow_origin:
            response.headers["Access-Control-Allow-Origin"] = allow_origin
            if allow_origin != "*":
                # Necessario quando si fa echo dell'Origin per cache/proxy corretti
                response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-API-Key"
        return response

app.add_middleware(ForceCORSMiddleware)

# ── AUTENTICAZIONE A SESSIONE ───────────────────────────────────────────────────
# Tutti gli endpoint /api/* richiedono un token di sessione valido (Authorization:
# Bearer <token>), emesso da /api/auth/login dopo verifica username+password.
# Le funzioni _verify_token / _bearer_token / _cors_allow_origin sono definite più
# avanti nel modulo: vengono risolte a runtime (il modulo è già caricato quando una
# richiesta arriva), quindi l'ordine non è un problema.

# Path /api/* che NON richiedono una sessione utente (hanno auth propria o sono pubblici)
_AUTH_EXEMPT_PATHS = {
    "/api/auth/login",        # pubblico: serve a ottenere il token
    "/api/auth/create-user",  # protetto separatamente da ADMIN_KEY
    "/api/cron-sync",         # protetto separatamente da CRON_API_KEY (Bearer dedicato)
    "/api/library/check-urls",# diagnostico: ha un proprio controllo a chiave
}


class AuthMiddleware(BaseHTTPMiddleware):
    """Richiede un token di sessione valido su tutti gli /api/* non esentati."""
    async def dispatch(self, request: StarletteRequest, call_next):
        path = request.url.path
        if (request.method != "OPTIONS"
                and path.startswith("/api/")
                and path not in _AUTH_EXEMPT_PATHS):
            if not _verify_token(_bearer_token(request)):
                resp = StarletteResponse(
                    content='{"detail":"Non autenticato"}',
                    status_code=401,
                    media_type="application/json"
                )
                resp.headers["Access-Control-Allow-Origin"] = _cors_allow_origin(request) or "*"
                return resp
        return await call_next(request)

app.add_middleware(AuthMiddleware)

# ── RATE LIMITING ──────────────────────────────────────────────────────────────
# Rate limiting in-memory sugli endpoint AI costosi.
# Nessuna dipendenza esterna — dict + timestamp unix.
# Si azzera a ogni restart Railway (accettabile per single-tenant).

_rl_buckets: dict = defaultdict(list)
_rl_mutex = threading.Lock()

# (path_prefix, max_requests, window_seconds)
_RATE_LIMITS: list = [
    ("/api/auth/login",    20,  900),  # anti-brute-force login (per IP) — 20/15min
    ("/api/library/sync",  10, 3600),  # sync catalogo — molto costoso
    ("/api/cron-sync",      5, 3600),  # cron sync — estremamente costoso
    ("/api/extract",       20, 3600),  # estrazione singola CGA
    ("/api/match",         60, 3600),  # matching
    ("/api/raccomanda",    30, 3600),  # raccomandazione
    ("/api/summary",       30, 3600),  # summary AI
]


def _rl_check(path: str, api_key: str) -> tuple:
    """Controlla rate limit. Ritorna (allowed, limit_or_None)."""
    for prefix, max_req, window in _RATE_LIMITS:
        if path.startswith(prefix):
            bucket_key = f"{api_key[:16]}|{prefix}"
            now = time.time()
            with _rl_mutex:
                hits = [t for t in _rl_buckets[bucket_key] if now - t < window]
                if len(hits) >= max_req:
                    return False, max_req
                hits.append(now)
                _rl_buckets[bucket_key] = hits
            return True, max_req
    return True, None


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Applica rate limiting agli endpoint AI costosi."""
    async def dispatch(self, request: StarletteRequest, call_next):
        if request.method != "OPTIONS":
            # Identità del bucket: token/chiave se presente, altrimenti IP client
            # (così il login senza credenziali è limitato per IP, anti-brute-force).
            api_key = (request.headers.get("X-API-Key", "")
                       or _bearer_token(request)
                       or (request.client.host if request.client else "")
                       or "anon")
            allowed, limit = _rl_check(request.url.path, api_key)
            if not allowed:
                resp = StarletteResponse(
                    content=f'{{"detail":"Rate limit superato — max {limit} richieste/ora"}}',
                    status_code=429,
                    media_type="application/json"
                )
                resp.headers["Access-Control-Allow-Origin"] = "*"
                resp.headers["Retry-After"] = "3600"
                return resp
        return await call_next(request)

app.add_middleware(RateLimitMiddleware)

# ── CLIENT ANTHROPIC (ASYNC) ──────────────────────────────────────────────────
client = anthropic.AsyncAnthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ── MODELLI ───────────────────────────────────────────────────────────────────
# Centralizzati qui e sovrascrivibili da env, così cambiare/aggiornare un modello
# NON richiede di toccare il codice in più punti.
# NOTA: verifica che "claude-opus-4-6" sia ancora attivo/non deprecato. Per usare
# un Opus più recente basta impostare la env var MODEL_VISION (es. claude-opus-4-8)
# su Railway, senza modificare il codice.
# .strip() difensivo: un valore env con uno spazio di troppo (es. "claude-opus-4-8 ")
# farebbe fallire TUTTE le chiamate con un 404 "model not found".
MODEL_VISION = os.getenv("MODEL_VISION", "claude-opus-4-6").strip()            # estrazione PDF vision + sezioni
MODEL_TEXT   = os.getenv("MODEL_TEXT",   "claude-sonnet-4-6").strip()          # estrazione/raffinamento da testo + match
MODEL_FAST   = os.getenv("MODEL_FAST",   "claude-haiku-4-5-20251001").strip()  # raccomandazioni, summary, detect tipo

# ── LIMITI PDF ────────────────────────────────────────────────────────────────
# Tetti generosi: pensati SOLO per fermare upload abnormi/abusi, non per bloccare
# le polizze lunghe. Una CGA lunga reale rientra ampiamente in questi limiti.
# Sovrascrivibili da env su Railway.
MAX_PDF_BYTES = int(os.getenv("MAX_PDF_BYTES", str(40 * 1024 * 1024)))  # 40 MB
MAX_PDF_PAGES = int(os.getenv("MAX_PDF_PAGES", "400"))                  # ~400 pagine

# ── QDRANT — PERSISTENZA DATI (via REST API dirette) ──────────────────────────
# Usiamo httpx invece del client qdrant-client per maggiore affidabilità e
# visibilità degli errori. Nessuna dipendenza da librerie esterne aggiuntive.

QDRANT_URL        = os.getenv("QDRANT_URL", "").rstrip("/")
QDRANT_API_KEY    = os.getenv("QDRANT_API_KEY", "")
QDRANT_COLLECTION = "polizza_facile_data"

# ID fissi UUID per i documenti GLOBALI (legacy) nella collezione.
# I dati personali (clienti/polizze/config) sono ora PER-UTENTE: vedi _user_pid().
# Questi ID legacy restano solo per la migrazione una-tantum dei dati esistenti.
_CLIENTS_PID = "00000000-0000-0000-0000-000000000001"
_POLIZZE_PID = "00000000-0000-0000-0000-000000000002"
_CONFIG_PID  = "00000000-0000-0000-0000-000000000003"
_USERS_PID   = "00000000-0000-0000-0000-000000000010"  # store account assicuratori (globale)

# Namespace per generare ID punto deterministici per-utente
_PID_NAMESPACE = uuid.UUID("00000000-0000-0000-0000-0000000000ff")

def _user_pid(kind: str, username: str) -> str:
    """ID Qdrant deterministico per i dati privati di un utente (kind: clients|polizze|config)."""
    return str(uuid.uuid5(_PID_NAMESPACE, f"{kind}:{username}"))

_qdrant_ok = False  # True se la connessione è stata verificata con successo


def _qh() -> dict:
    """Header per le richieste Qdrant REST."""
    h = {"Content-Type": "application/json"}
    if QDRANT_API_KEY:
        h["api-key"] = QDRANT_API_KEY
    return h


@app.on_event("startup")
async def _startup():
    global _qdrant_ok
    if not QDRANT_URL:
        logger.warning("QDRANT_URL non configurato — persistenza Qdrant disabilitata")
        return
    try:
        async with httpx.AsyncClient(timeout=15.0) as http:
            logger.info(f"Qdrant: connessione a {QDRANT_URL}")
            r = await http.get(f"{QDRANT_URL}/collections/{QDRANT_COLLECTION}", headers=_qh())
            if r.status_code == 200:
                logger.info(f"Qdrant: collezione '{QDRANT_COLLECTION}' trovata — ok")
                _qdrant_ok = True
            elif r.status_code == 404:
                logger.info(f"Qdrant: creazione collezione '{QDRANT_COLLECTION}'...")
                r2 = await http.put(
                    f"{QDRANT_URL}/collections/{QDRANT_COLLECTION}",
                    headers=_qh(),
                    json={"vectors": {"size": 1, "distance": "Cosine"}}
                )
                if r2.status_code in (200, 201):
                    logger.info(f"Qdrant: collezione creata con successo")
                    _qdrant_ok = True
                else:
                    logger.error(f"Qdrant: creazione fallita {r2.status_code}: {r2.text[:200]}")
            else:
                logger.error(f"Qdrant: risposta inattesa {r.status_code}: {r.text[:200]}")
    except Exception as e:
        logger.error(f"Qdrant startup FALLITO ({type(e).__name__}): {e}")
        _qdrant_ok = False

    # Seed account iniziale (solo se ADMIN_USERNAME/ADMIN_PASSWORD impostati e non esiste già)
    if _qdrant_ok and ADMIN_USERNAME and ADMIN_PASSWORD:
        try:
            users = await _load_users()
            if ADMIN_USERNAME not in users:
                users[ADMIN_USERNAME] = {"pwd": _hash_password(ADMIN_PASSWORD), "created": int(time.time())}
                await _save_users(users)
                logger.info(f"Auth: account seed '{ADMIN_USERNAME}' creato")
        except Exception as e:
            logger.error(f"Auth: seed account fallito: {e}")

    # Migrazione una-tantum: copia i dati legacy GLOBALI (clienti/polizze/config)
    # nello spazio privato dell'account proprietario indicato da DATA_OWNER_USERNAME.
    # Copia solo se lo spazio dell'utente è vuoto e i dati legacy esistono.
    if _qdrant_ok and DATA_OWNER_USERNAME:
        try:
            for kind, legacy_pid in (("clients", _CLIENTS_PID), ("polizze", _POLIZZE_PID), ("config", _CONFIG_PID)):
                target_pid = _user_pid(kind, DATA_OWNER_USERNAME)
                existing = await _q_get(target_pid)
                legacy = await _q_get(legacy_pid)
                if (existing is None or existing == [] or existing == {}) and legacy not in (None, [], {}):
                    await _q_set(target_pid, legacy)
                    logger.info(f"Migrazione: dati legacy '{kind}' → account '{DATA_OWNER_USERNAME}'")
        except Exception as e:
            logger.error(f"Migrazione dati legacy fallita: {e}")


async def _q_get(point_id: str):
    """Legge il payload di un punto Qdrant via REST."""
    if not QDRANT_URL or not _qdrant_ok:
        return None
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            r = await http.get(
                f"{QDRANT_URL}/collections/{QDRANT_COLLECTION}/points/{point_id}",
                headers=_qh()
            )
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json().get("result", {}).get("payload", {}).get("data")
    except Exception as e:
        logger.error(f"Qdrant get {point_id}: {e}")
        return None


# Lock per-point per serializzare le scritture sullo stesso documento
# (evita race read-modify-write su un singolo blob).
_q_locks: dict = defaultdict(asyncio.Lock)


async def _q_set(point_id: str, data) -> bool:
    """
    Salva (upsert) un punto Qdrant via REST.
    Ritorna True se persistito, False se la persistenza non è configurata.
    Lancia RuntimeError se il salvataggio fallisce davvero (così il chiamante
    può rispondere con un errore onesto invece di un falso 'ok').
    """
    if not QDRANT_URL or not _qdrant_ok:
        return False  # persistenza non disponibile (es. dev senza Qdrant)
    async with _q_locks[point_id]:
        try:
            async with httpx.AsyncClient(timeout=10.0) as http:
                r = await http.put(
                    f"{QDRANT_URL}/collections/{QDRANT_COLLECTION}/points",
                    headers=_qh(),
                    json={"points": [{"id": point_id, "vector": [0.0], "payload": {"data": data}}]}
                )
                r.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Qdrant set {point_id}: {e}")
            raise RuntimeError(f"Salvataggio Qdrant fallito: {e}")


# ── ENDPOINTS DATI PERSISTENTI (PER-UTENTE) ───────────────────────────────────
# Clienti, polizze e configurazione sono privati di ciascun account assicuratore.
# La libreria CGA (più in basso) resta invece condivisa fra tutti gli account.

def _current_user(request: Request) -> str:
    """Username dal token di sessione (l'AuthMiddleware ha già garantito che sia valido)."""
    u = _verify_token(_bearer_token(request))
    if not u:
        raise HTTPException(401, "Non autenticato")
    return u

@app.get("/api/clients")
async def api_get_clients(request: Request):
    data = await _q_get(_user_pid("clients", _current_user(request)))
    return data if data is not None else []

@app.post("/api/clients")
async def api_save_clients(req: Request):
    user = _current_user(req)
    body = await req.json()
    try:
        persisted = await _q_set(_user_pid("clients", user), body.get("data", []))
    except RuntimeError:
        raise HTTPException(503, "Salvataggio clienti non riuscito — riprova tra poco")
    return {"ok": True, "persisted": persisted}

@app.get("/api/polizze")
async def api_get_polizze(request: Request):
    data = await _q_get(_user_pid("polizze", _current_user(request)))
    return data if data is not None else []

@app.post("/api/polizze")
async def api_save_polizze(req: Request):
    user = _current_user(req)
    body = await req.json()
    try:
        persisted = await _q_set(_user_pid("polizze", user), body.get("data", []))
    except RuntimeError:
        raise HTTPException(503, "Salvataggio polizze non riuscito — riprova tra poco")
    return {"ok": True, "persisted": persisted}

@app.get("/api/config")
async def api_get_config(request: Request):
    data = await _q_get(_user_pid("config", _current_user(request)))
    return data if data is not None else {}

@app.post("/api/config")
async def api_save_config(req: Request):
    user = _current_user(req)
    body = await req.json()
    try:
        persisted = await _q_set(_user_pid("config", user), body.get("data", {}))
    except RuntimeError:
        raise HTTPException(503, "Salvataggio configurazione non riuscito — riprova tra poco")
    return {"ok": True, "persisted": persisted}

# ── AUTENTICAZIONE: HELPER + ENDPOINTS ──────────────────────────────────────────
# Account per assicuratore. Password salvate con hash PBKDF2-SHA256 (mai in chiaro).
# Token di sessione stateless firmati HMAC-SHA256 con scadenza — nessuna dipendenza
# esterna, nessuno stato server-side da gestire.

SESSION_SECRET = os.getenv("SESSION_SECRET", "")
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_hex(32)
    logger.warning(
        "SESSION_SECRET non impostato — uso un segreto effimero: i login si "
        "invalideranno a ogni restart. Imposta SESSION_SECRET su Railway."
    )
ADMIN_KEY = os.getenv("ADMIN_KEY", "")  # protegge la creazione account
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_HOURS", "168")) * 3600  # default 7 giorni
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
# Account a cui assegnare i dati legacy globali esistenti (migrazione una-tantum)
DATA_OWNER_USERNAME = os.getenv("DATA_OWNER_USERNAME", "").strip().lower()


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _hash_password(password: str, iterations: int = 200_000, salt: bytes = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        _algo, iters, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def _make_token(username: str, ttl: int = None) -> str:
    exp = int(time.time()) + (ttl or SESSION_TTL_SECONDS)
    body = _b64url(json.dumps({"u": username, "exp": exp}).encode())
    sig = _b64url(hmac.new(SESSION_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"

def _verify_token(token: str):
    """Ritorna lo username se il token è valido e non scaduto, altrimenti None."""
    if not token:
        return None
    try:
        body, sig = token.split(".")
        expected = _b64url(hmac.new(SESSION_SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_b64url_dec(body))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload.get("u")
    except Exception:
        return None


def _bearer_token(request) -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return request.headers.get("X-Auth-Token", "") or request.query_params.get("token", "")


async def _load_users() -> dict:
    data = await _q_get(_USERS_PID)
    return data if isinstance(data, dict) else {}

async def _save_users(users: dict) -> bool:
    return await _q_set(_USERS_PID, users)


class LoginRequest(BaseModel):
    username: str
    password: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    admin_key: str = ""


@app.post("/api/auth/login")
async def auth_login(req: LoginRequest):
    uname = req.username.strip().lower()
    users = await _load_users()
    rec = users.get(uname)
    # Verifica anche in caso di utente inesistente per non rivelare quali username esistono
    stored = rec.get("pwd", "") if rec else ""
    if not rec or not _verify_password(req.password, stored):
        raise HTTPException(401, "Username o password non validi")
    return {
        "token": _make_token(uname),
        "username": uname,
        "expires_in": SESSION_TTL_SECONDS,
    }


@app.get("/api/auth/me")
async def auth_me(request: Request):
    u = _verify_token(_bearer_token(request))
    if not u:
        raise HTTPException(401, "Non autenticato")
    return {"username": u}


@app.post("/api/auth/create-user")
async def auth_create_user(req: CreateUserRequest, request: Request):
    if not ADMIN_KEY:
        raise HTTPException(403, "Creazione account disabilitata: imposta ADMIN_KEY su Railway")
    key = req.admin_key or request.headers.get("X-Admin-Key", "")
    if not hmac.compare_digest(key, ADMIN_KEY):
        raise HTTPException(401, "Admin key non valida")
    uname = req.username.strip().lower()
    if not uname or len(req.password) < 8:
        raise HTTPException(400, "Username obbligatorio e password di almeno 8 caratteri")
    users = await _load_users()
    is_new = uname not in users
    users[uname] = {
        "pwd": _hash_password(req.password),
        "created": users.get(uname, {}).get("created", int(time.time())),
        "updated": int(time.time()),
    }
    try:
        await _save_users(users)
    except RuntimeError:
        raise HTTPException(503, "Persistenza non disponibile: impossibile salvare l'account")
    return {"ok": True, "username": uname, "created": is_new, "total_users": len(users)}

# ── GESTIONE ERRORI API AI ──────────────────────────────────────────────────
def _ai_error_message(exc) -> str | None:
    """
    Se l'eccezione è un errore del servizio AI (non un problema di contenuto),
    ritorna un messaggio chiaro per l'utente; altrimenti None.
    Serve a mostrare es. "Crediti AI esauriti" invece di "Nessun dato estratto".
    """
    try:
        if isinstance(exc, anthropic.AuthenticationError):
            return "Configurazione AI non valida (chiave API). Contatta l'assistenza."
        if isinstance(exc, anthropic.RateLimitError):
            return "Servizio AI sovraccarico in questo momento — riprova tra qualche minuto."
        if isinstance(exc, anthropic.APIStatusError):
            msg = str(getattr(exc, "message", "") or exc).lower()
            code = getattr(exc, "status_code", 0)
            if code == 402 or "credit" in msg or "billing" in msg or "quota" in msg:
                return "Crediti AI esauriti: ricarica il credito Anthropic per continuare l'estrazione."
            return "Servizio AI temporaneamente non disponibile — riprova più tardi."
        if isinstance(exc, (anthropic.APIConnectionError, anthropic.APITimeoutError)):
            return "Impossibile contattare il servizio AI (connessione) — riprova."
    except Exception:
        pass
    return None


# ── RETRY HELPER ──────────────────────────────────────────────────────────────
async def call_claude(max_retries: int = 3, **kwargs):
    """Chiama Claude con retry automatico su errori 529 (overloaded)."""
    for attempt in range(max_retries):
        try:
            return await client.messages.create(**kwargs)
        except anthropic.APIStatusError as e:
            if e.status_code == 529 and attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)  # 1s, 2s, 4s
                continue
            raise
    raise HTTPException(503, "Servizio AI temporaneamente non disponibile, riprova tra qualche secondo")


# ── TASSONOMIA GARANZIE E CATEGORIE STANDARD ─────────────────────────────────
# Usata nel prompt di estrazione per normalizzare nomi e categorie delle garanzie
# in modo che polizze diverse usino gli stessi termini → tabella comparativa coerente.

TASSONOMIA_GARANZIE = """
TASSONOMIA GARANZIE STANDARD — usa questi nomi ESATTI per il campo "nome" quando la garanzia corrisponde:

POLIZZE CASA / MULTIRISCHIO:
- "Incendio e danni alla proprietà"  (include: incendio, fulmine, esplosione, scoppio, fumo, gas, danni da calore)
- "Furto e rapina in casa"           (include: furto, rapina, scippo dentro l'abitazione, tentato furto)
- "Danni da acqua"                   (include: perdite occulte, allagamento da tubature interne, infiltrazioni)
- "Danni elettrici"                  (include: sovratensione, cortocircuito, guasti a impianti elettrici)
- "Eventi atmosferici"               (include: grandine, vento, neve, tempesta, nubifragio)
- "Vetri e cristalli"
- "Responsabilità civile verso terzi" (RC capofamiglia, RC vita privata, RC locatario)
- "Tutela legale"
- "Assistenza casa"                  (include: pronto intervento, idraulico h24, elettricista d'urgenza)
- "Terremoto"
- "Alluvione e inondazione"
- "Furto e scippo fuori casa"        (include: scippo, rapina fuori dall'abitazione, borseggio)
- "Preziosi e valori"
- "Impianto fotovoltaico"
- "Ricerca guasto"
- "Rischio locativo"                 (danni all'immobile di cui si è responsabili come locatario)

POLIZZE INFORTUNI / SALUTE / PERSONA:
- "Invalidità permanente da infortunio"
- "Decesso da infortunio"           (include: "morte da infortuni", "capitale caso morte da infortuni" — mappa SEMPRE a questo nome standard)
- "Invalidità permanente da malattia"
- "Invalidità permanente da ictus o infarto"
- "Invalidità permanente grave da malattia"
- "Rendita vitalizia"
- "Rimborso spese mediche"           (include: spese di cura, spese sanitarie da infortunio o malattia)
- "Diaria da ricovero"               (include: indennità giornaliera di ricovero ospedaliero)
- "Diaria post ricovero"             (include: convalescenza, post-ricovero)
- "Inabilità temporanea al lavoro"   (include: indennità giornaliera per inabilità lavorativa)
- "Diaria da immobilizzazione"
- "Tutela legale"
- "Assistenza sanitaria"             (include: assistenza per infortuni, SiSalute, medico h24)
- "Sostegno e protezione"
- "Diaria da ricovero prolungato"
- "Stato comatoso irreversibile"

POLIZZE VITA / RISPARMIO / PREVIDENZA:
- "Caso morte"
- "Caso vita / rendita a scadenza"
- "Invalidità totale permanente (ITP)"
- "Malattie gravi (Dread Disease)"
- "Long Term Care (LTC)"
- "Esonero dal pagamento premi"

POLIZZE RC AUTO / VEICOLI:
- "Responsabilità civile auto (RCA)"
- "Kasko"
- "Furto e incendio auto"
- "Eventi naturali auto"             (include: grandine, allagamento, caduta alberi su veicolo)
- "Cristalli auto"
- "Tutela legale auto"
- "Assistenza stradale"
- "Infortuni conducente e passeggeri"

Se una garanzia non corrisponde a nessuna delle voci sopra: usa il nome più descrittivo e conciso possibile.
NON inventare varianti di nomi già presenti nella lista — usa SEMPRE il termine standard.
"""

TASSONOMIA_CATEGORIE = """
TASSONOMIA CATEGORIE STANDARD — usa ESATTAMENTE uno di questi valori per il campo "categoria":
- "Danni alla proprietà"      (incendio, furto, acqua, elettrico, atmosferici, vetri, terremoto, alluvione)
- "Responsabilità Civile"     (RC verso terzi, RC capofamiglia, RC vita privata, RC locatario)
- "Infortuni"                 (invalidità da infortunio, decesso da infortunio, diaria, inabilità)
- "Salute e Malattia"         (invalidità da malattia, spese mediche, rimborsi sanitari, dread disease)
- "Assistenza"                (assistenza casa, assistenza sanitaria, assistenza stradale, pronto intervento)
- "Tutela Legale"             (tutela legale in qualsiasi tipo di polizza)
- "Vita e Risparmio"          (caso morte, caso vita, LTC, rendita, esonero premi)
- "Veicoli"                   (RCA, kasko, cristalli auto, eventi naturali auto)
- "Altro"                     (qualsiasi garanzia che non rientra nelle categorie sopra)
"""

# ── CACHE ─────────────────────────────────────────────────────────────────────
import hashlib
_extraction_cache: dict[str, dict] = {}  # hash → risultato estratto

def _cache_key(text: str) -> str:
    """Chiave cache basata su hash MD5 del testo (primi 2000 + lunghezza totale)."""
    fingerprint = f"{len(text)}:{text[:2000]}:{text[-500:]}"
    return hashlib.md5(fingerprint.encode()).hexdigest()

# ── MODELS ────────────────────────────────────────────────────────────────────
class ExtractRequest(BaseModel):
    text: str
    filename: str

class SummaryRequest(BaseModel):
    policies: list = Field(..., min_length=2, max_length=6)
    client_profile: dict = Field(default_factory=dict)

class RaccomandaRequest(BaseModel):
    risposte: dict
    agenzia: str = "default"

class MatchRequest(BaseModel):
    client: dict
    policies: list = Field(..., min_length=1, max_length=4)
    feedback_history: list = Field(default_factory=list, max_length=20)


# ── EXTRACTION HELPERS ────────────────────────────────────────────────────────

def _build_extraction_prompt(text_chunk: str, filename: str, chunk_info: str = "") -> str:
    chunk_note = f"\n[NOTA: stai analizzando {chunk_info} del documento — estrai TUTTE le garanzie trovate in questa parte]\n" if chunk_info else ""
    return f"""Sei un esperto di polizze assicurative italiane. Analizza il testo estratto da una polizza e restituisci SOLO un oggetto JSON valido, nessun altro testo.
{chunk_note}
{TASSONOMIA_GARANZIE}
{TASSONOMIA_CATEGORIE}

TESTO POLIZZA (file: {filename}):
<testo_polizza>
{text_chunk}
</testo_polizza>

Schema JSON richiesto:
{{
  "compagnia": "nome compagnia assicuratrice",
  "prodotto": "nome commerciale del prodotto",
  "tipo": "categoria principale: RC Auto | Casa | Vita | Infortuni | Salute | Multirischio | Risparmio | altro",
  "premio": "importo e periodicità come scritto nel documento, oppure null se non trovato",
  "garanzie": [
    {{
      "categoria": "ESATTAMENTE uno dei valori dalla TASSONOMIA CATEGORIE sopra",
      "nome": "nome NORMALIZZATO dalla tassonomia garanzie — usa ESATTAMENTE uno dei termini elencati se applicabile",
      "presente": true,
      "opzionale": false,
      "massimale": "importo ESATTO scritto nel documento es: 500.000 € — oppure 'Somma assicurata' per polizze casa/multirischio — oppure null",
      "massimale_num": 500000,
      "franchigia": "es: 250 € o 5% — oppure null",
      "scoperto": "es: 10% min. €250 — includi SEMPRE il minimo in € se presente (es: '10% min. €10.000') — oppure null",
      "note": "IMPORTANTE: per polizze casa includi TUTTI i sublimiti in questo campo nel formato: 'Sublimiti: [voce]: [limite]'. Es: 'Sublimiti: Preziosi max 10% SA/€10.000 | Valori max 5% SA/€2.500 | Dipendenze max 20% SA scoperto 10% min €250 | Lavoratori domestici max 50% SA/€10.000'. Includi anche: massimale RC (es: €5.000.000), limiti assistenza (es: €250/intervento, €300/albergo)."
    }}
  ],
  "punti_di_forza": ["punto concreto e specifico 1", "punto concreto 2", "punto concreto 3"],
  "consigliata_per": "profilo cliente ideale in 1 frase concreta",
  "esclusioni": ["esclusione rilevante 1", "esclusione 2"]
}}

Regole CRITICHE:
- nome: usa SEMPRE un termine dalla tassonomia garanzie se applicabile — MAI inventare varianti
- categoria: usa SEMPRE uno dei 9 valori dalla tassonomia categorie — MAI inventare categorie nuove
- massimale_num: valore numerico puro (es: 500000), 0 se non trovato o non applicabile
- massimale: cerca ATTIVAMENTE i valori Euro nelle TABELLE del DIP, nelle Schede Tecniche, nei "Limiti di indennizzo", nelle "Somme assicurate", nei "Capitali assicurati", nelle "Condizioni specifiche", nelle righe "Massimale per sinistro", "Limite per evento", "Indennizzo massimo" — riporta il valore ESATTO trovato (es: "500.000 €", "2.500.000 €")
- POLIZZE CASA / MULTIRISCHIO: Per queste polizze il massimale principale (Incendio, Furto) è la "Somma Assicurata" (SA), un valore scelto dal cliente non presente nel testo. In questo caso usa massimale="Somma assicurata" e massimale_num=0. PERÒ estrai OBBLIGATORIAMENTE nel campo note tutti i sublimiti trovati con formato "Sublimiti: X | Y | Z": es. gioielli, valori, preziosi, dipendenze, lavoratori domestici, alloggio sostitutivo, spese demolizione, etc.
- ECCEZIONE CRITICA CASA: RC (Responsabilità Civile) e Tutela Legale NON usano "Somma assicurata" — di norma hanno massimali FISSI nel testo (es: RC tipicamente €5.000.000/sinistro). Estraili sempre. ATTENZIONE: alcune polizze (es. Zurich, ITAS) hanno il massimale RC "indicato in Polizza" (scelto dal cliente) — in questo caso usa massimale="Indicato in Polizza" e massimale_num=0. Idem per Assistenza casa: ha limiti fissi per tipo di intervento da mettere nel campo note come "Sublimiti: ...". Se l'assistenza è strutturata in "base" e "plus", riporta i sublimiti di entrambe nel campo note separandole: "BASE: Idraulico max €X | Vetraio max €Y | ... PLUS: Idraulico max €Z | Asciugatura max €W | ...".
- POLIZZE INFORTUNI: Tutte le garanzie (Decesso, Invalidità permanente, Diaria, Rimborso spese) hanno massimale = "Somma assicurata" (importo scelto dal cliente). USA SEMPRE massimale="Somma assicurata" per queste. MA cerca nella sezione "TABELLA RIASSUNTIVA DI LIMITI, FRANCHIGIE E/O SCOPERTI" tutti gli scoperti e franchigie: es. "Scoperto 20% con il minimo di €75 per rimborso spese" → scoperto="20% min. €75"; "5 giorni se diaria ≤ €50; 10 giorni se €50-€80; 15 giorni se >€80" → franchigia="5/10/15 giorni (in base alla diaria scelta)". Franchigia invalidità permanente: "Franchigia 5%" o "Franchigia 0% per IP ≥ 20%".
- POLIZZE RC AUTO / VEICOLI: Regole precise per ogni garanzia: (1) RCA — massimale FISSO nel testo, estrai i valori ESATTI (es: "€6.450.000 lesioni + €1.300.000 cose" oppure massimale unico es: "€7.500.000"). MAI usare "Somma assicurata". Cerca nelle tabelle "Massimali di garanzia", "Limiti di risarcimento", DIP Aggiuntivo sezione RCA. Nel campo note includi: rivalsa per ebbrezza/droghe (sì/no e importo), guida esclusiva/esperta/libera, clausola bonus protetto se presente. (2) Kasko — massimale = "Valore del veicolo" (determinato al momento del sinistro, non fisso nel testo) → usa massimale="Valore del veicolo" e massimale_num=0. Franchigia: riporta il valore ESATTO trovato (es: "€500 fisso", "10% min. €300"). Scoperto: includi sempre il minimo € (es: "15% min. €500"). Nel note: tipo di valutazione del veicolo (valore commerciale/vetusto/a nuovo), vetustà applicata, eventuali franchigie differenziate per tipo di danno. (3) Furto e incendio auto — massimale = "Valore del veicolo" oppure "Valore commerciale del veicolo" → usa massimale="Valore del veicolo" e massimale_num=0. Franchigia furto: tipicamente 10-15% del valore o fissa. Nel note: limite massimo di indennizzo se presente, scoperti differenziati furto/incendio, franchigia tentato furto. (4) Cristalli auto — il massimale può essere FISSO (es: "€1.500 per parabrezza") oppure "Valore del cristallo" → estrai quello che trovi. Franchigia: riporta il valore esatto (es: "€100", "€250"). (5) Assistenza stradale — nel campo note includi TUTTI i sublimiti trovati: max km per traino, numero eventi/anno, copertura estero (sì/no), auto sostitutiva (giorni max), recupero veicolo, albergo (notti max e €/notte), proseguimento viaggio. Usa massimale=null se non c'è un massimale monetario unico. (6) Infortuni conducente e passeggeri — ha massimali FISSI: estrai morte (es: "€100.000") e invalidità permanente (es: "€200.000") come garanzie separate se distinte nel testo, oppure come unica voce con sublimiti nel campo note: "Morte: €100.000 | IP: €200.000 | Diaria ricovero: €X/gg". Usa massimale_num con il valore più alto. (7) Tutela legale auto — massimale FISSO (es: "€40.000/anno, €10.000/sinistro") → estrai sempre. Nel note: include spese legali sì/no, peritali, carenze. (8) Eventi naturali auto — massimale = "Valore del veicolo" → usa massimale="Valore del veicolo". Nel note: franchigia %, elenco eventi coperti (grandine, allagamento, caduta oggetti, ecc.). REGOLA GENERALE RC AUTO: cerca SEMPRE nelle sezioni "DIP", "DIP Aggiuntivo", "Condizioni di Assicurazione", "Scheda Sintetica", "Tabella delle garanzie" — queste polizze per legge devono riportare tutti i massimali.
- TABELLE: le tabelle PDF si presentano spesso come righe di testo allineato — cerca pattern come "Garanzia | Massimale | Franchigia" o "Nome garanzia ... €XXX.XXX" e leggi i valori numerici corrispondenti a ogni garanzia
- franchigia: cerca nelle tabelle "Franchigie", "Scoperti", "Limitazioni", "Soglie", "Minimale" — riporta il valore ESATTO. ATTENZIONE: una franchigia può essere per sotto-garanzia (es: "Franchigia €250 per acqua piovana/allagamenti" va riportata anche se l'incendio in sé non ha franchigia). Per POLIZZE INFORTUNI: la franchigia può essere espressa in GIORNI (es: "franchigia di 5 giorni" per diaria) — scrivi "5 giorni" oppure "5/10/15 giorni (in base all'importo scelto)" se la franchigia è variabile.
- scoperto: FONDAMENTALE — includi SEMPRE il minimo in € quando presente. Es: "10% min. €10.000" NON solo "10%". Questo è critico per: Terremoto, Alluvione, Furto (polizze casa) E ANCHE per Rimborso spese mediche (polizze infortuni: tipicamente "20% min. €75"). Pattern da cercare: "Scoperto X% con il minimo di €YYY" → scrivi "X% min. €YYY".
- presente: true se la garanzia è inclusa nel pacchetto base; false altrimenti
- opzionale: true se è un supplemento acquistabile a pagamento; false se è completamente assente dal prodotto
- Includi TUTTE le garanzie menzionate nel testo, anche quelle opzionali
- PRODOTTI MODULARI: se il prodotto è composto da moduli (es. Modulo Casa, Modulo Salute, Modulo Armonia, Modulo Persona), estrai le garanzie di OGNI modulo con i loro massimali specifici — trattale tutte come parte dello stesso prodotto
- punti_di_forza: 3 vantaggi concreti e specifici con valori numerici dove disponibili, NON generici
- esclusioni: massimo 6, solo le più rilevanti per un cliente medio
- Se il testo è parziale (brochure, DIP, set informativo), estrai comunque tutto il possibile
- REGOLA ASSOLUTA SUL CAMPO NOTE E DESCRIZIONE: è VIETATO scrivere qualsiasi frase del tipo "verificare ...", "da verificare ...", "non dettagliato nel testo", "non riportato nel testo estratto", "vedere scheda di polizza", "vedere tipologia scelta in scheda", "vedere condizioni di assicurazione", "vedere tabella sezione", "presente nella tabella sezione X", "tipologia scelta in polizza", "in base alla tipologia scelta", "definita in polizza", "come da scheda" — queste frasi sono inutili per l'utente. Se trovi il valore nel testo, scrivilo. Se NON lo trovi, lascia note=null (non spiegare perché non l'hai trovato). Per garanzie con più opzioni di franchigia (es. IP con Fr. 5%, 25%, progressiva): riporta la franchigia standard/più comune nel campo franchigia (es. "5%"), e le varianti disponibili nel campo note (es. "Varianti: Fr. 3% assorbibile, Fr. 10%, Fr. 25%") — MAI riferirsi alla scheda di polizza. I valori FISSI come €250/evento assistenza, massimale RC €5.000.000, sublimiti furto (gioielli max €15.000, valori max €2.500) SONO nelle CG — estraili e scrivili esplicitamente."""


def _build_refinement_prompt(merged: dict, dense_text: str, filename: str) -> str:
    """Prompt per il pass di raffinamento con Opus: arricchisce massimali, sublimiti e franchigie mancanti."""
    garanzie_mancanti = [
        g["nome"] for g in merged.get("garanzie", [])
        if not g.get("massimale_num") or g.get("massimale_num") == 0
    ]
    # Garanzie con sublimiti mancanti nelle note
    SEZIONI_SUBLIMITI = [
        # Casa
        "Furto e rapina in casa", "Incendio e danni alla proprietà",
        "Responsabilità civile verso terzi", "Assistenza casa",
        "Terremoto", "Alluvione e inondazione",
        # Infortuni — assistenza e rimborsi
        "Assistenza sanitaria", "Rimborso spese sanitarie da infortuni",
        "Rimborso spese sanitarie da malattia", "Tutela legale",
    ]
    garanzie_note_incomplete = [
        g["nome"] for g in merged.get("garanzie", [])
        if not g.get("note") and g.get("nome") in SEZIONI_SUBLIMITI
    ]
    # Garanzie infortuni con scoperto o franchigia in giorni mancante
    SEZIONI_INFORTUNI_NOMI = [
        "Rimborso spese mediche", "Rimborso spese mediche da infortuni",
        "Rimborso spese sanitarie da infortuni", "Rimborso spese sanitarie da malattia",
        "Diaria per inabilità temporanea al lavoro", "Diaria inabilità temporanea",
        "Diaria inabilità temporanea da malattia",
        "Diaria da ricovero", "Diaria ricovero", "Diaria post ricovero",
        "Diaria post-ricovero", "Diaria da immobilizzazione", "Diaria gesso / immobilizzazione",
        "Invalidità permanente da infortuni", "Invalidità permanente grave da infortuni",
        "Invalidità permanente da malattia", "Rendita vitalizia",
        "Rendita vitalizia da infortuni", "Rendita vitalizia da malattia",
    ]
    garanzie_infortuni_da_completare = [
        g["nome"] for g in merged.get("garanzie", [])
        if g.get("nome") in SEZIONI_INFORTUNI_NOMI
        and (not g.get("scoperto") or not g.get("franchigia"))
    ]
    garanzie_json = json.dumps(merged.get("garanzie", []), ensure_ascii=False, indent=2)
    return f"""Sei un esperto di polizze assicurative italiane con capacità di lettura precisa di tabelle e condizioni contrattuali.

Hai già estratto le garanzie di questa polizza (file: {filename}). Ora devi COMPLETARE i valori mancanti cercando nel testo originale.

GARANZIE GIÀ ESTRATTE (JSON attuale):
{garanzie_json}

GARANZIE CON MASSIMALE MANCANTE (massimale_num = 0):
{json.dumps(garanzie_mancanti, ensure_ascii=False)}

GARANZIE CON NOTE DA COMPLETARE — CASA (cerca sublimiti):
{json.dumps(garanzie_note_incomplete, ensure_ascii=False)}

GARANZIE INFORTUNI DA COMPLETARE (cerca scoperto con minimo, franchigie in giorni):
{json.dumps(garanzie_infortuni_da_completare, ensure_ascii=False)}

TESTO ORIGINALE DELLA POLIZZA (sezioni più dense con massimali e tabelle):
<testo_polizza>
{dense_text}
</testo_polizza>

COMPITO — RICERCA PRECISA IN 4 AREE:

NOTA TECNICA: il testo sotto è estratto da PDF italiano. Le tabelle possono essere "garbled" (colonne unite in righe), es: "Garanzia Massimale Franchigia Responsabilità Civile 5.000.000 € nessuna" tutto su una riga. Leggi i valori numerici nel loro contesto: il numero Euro dopo il nome della garanzia è il suo massimale.

**AREA 1 — MASSIMALI FISSI:**
Cerca per ogni garanzia con massimale mancante:
   - Tabelle DIP con colonne "Garanzia | Massimale | Franchigia"
   - Righe: "[nome garanzia] ... [€ XXX.XXX]" o "[€ XXX.XXX] ... [nome garanzia]"
   - Sezioni: "Limiti di indennizzo", "Somme assicurate", "Capitali assicurati", "Massimali"
   - Schede tecniche per modulo (es: Modulo Casa, Modulo Salute, Modulo Persona)
   - Valori come: "fino a €", "massimo €", "non oltre €", "pari a €"
   - MASSIMALE RC (CRITICO): cerca "limite massimo di risarcimento", "massimale per sinistro", "massimale di garanzia", "per sinistro €" nella sezione "Responsabilità Civile". Valore tipico per polizze casa: €5.000.000. Scrivi massimale="5.000.000 €" e massimale_num=5000000. NON lasciare RC con massimale=null se hai trovato un valore Euro vicino a "Responsabilità Civile" nel testo.
   - MASSIMALE TUTELA LEGALE: cerca "massimale tutela legale", "limite massimo spese legali", "fino a €" nella sezione "Tutela Legale". Scrivi massimale e massimale_num corrispondenti.

**AREA 2 — SUBLIMITI PERCENTUALI (importantissimo per polizze casa):**
Per le garanzie Furto, Incendio, RC, Assistenza cerca SPECIFICAMENTE:
   - Pattern "X% della somma assicurata per il contenuto con il massimo di € YYY" → scrivi "max X% SA contenuto / €YYY"
   - Pattern "X% della somma assicurata per il fabbricato" → scrivi "max X% SA fabbricato"
   - Pattern "fino ad un massimo di € ZZZ per sinistro" → scrivi "max €ZZZ/sinistro"
   - Pattern "fino ad un massimo di € ZZZ per evento" → scrivi "max €ZZZ/evento"
   - Sublimiti specifici per: preziosi, gioielli, valori, oggetti pregiati, dipendenze, lavoratori domestici,
     alloggio sostitutivo, spese demolizione/sgombero, rifacimento documenti, furto all'esterno
   - ASSISTENZA CASA (CRITICO): cerca negli articoli dedicati per tipo (es: "Invio idraulico", "Invio elettricista", "Invio fabbro") il limite per SINGOLO INVIO ARTIGIANO. Pattern da cercare: "tiene a proprio carico... fino a un massimo di €X per evento". Questo valore ESATTO va in garanzie_detail.assistenza.gz.ass_idraul.sub / ass_elett.sub / ass_fabbro.sub. NON usare valori da tabelle riassuntive. Scrivi nel campo note: "Sublimiti: Idraulico/Elettricista/Fabbro max €X/evento | Alloggio max €W/evento | ..."
   - ASSISTENZA — pattern "massimo complessivo + per artigiano": se trovi "massimo complessivo di €X per evento, con un massimo di €Y per artigiano" → aggiorna garanzie_detail.assistenza.gz.ass_idraul.sub=ass_elett.sub=ass_fabbro.sub="€ Y".
   - ASSISTENZA — alloggio ≠ artigiani: ass_allogg.sub (pernottamento/hotel) è SPESSO €300/evento; artigiani (idraulico/elettricista/fabbro) sono SPESSO €250/evento. Valori DISTINTI — non usare il valore alloggio per gli artigiani.
   - RC — rc_inquin: controlla se il testo della sezione RC esclude esplicitamente l'inquinamento. Se sì → garanzie_detail.rc.gz.rc_inquin=null. Se la RC è inclusa senza menzione dell'inquinamento → {"sub": null, "scop": null, "fra": null}.
   - INCENDIO — demolizione: riportare ESATTAMENTE la formulazione ("30% dell'indennizzo" ≠ "20% dell'indennizzo max €30.000" ≠ "5% del massimale"). Aggiorna garanzie_detail.incendio.gz.demolizione.sub con il testo esatto.
   - INCENDIO — ricerca_guasto: il sublimite massimo fisso si trova nell'articolo dedicato (es: "5% del valore assicurato alla partita fabbricato con il massimo di €2.500"). Aggiorna garanzie_detail.incendio.gz.ricerca_guasto.sub con il massimale fisso trovato (es: "€ 2.500").
   Metti tutti questi sublimiti nel campo "note" con formato: "Sublimiti: [voce] max [limite] | [voce] max [limite]"

**AREA 3 — SCOPERTI CON MINIMO (casa E infortuni):**
FONDAMENTALE — cerca TUTTE le sezioni "TABELLA RIASSUNTIVA DI LIMITI, FRANCHIGIE E/O SCOPERTI" e ogni tabella di franchigie:
   POLIZZE CASA:
   - Pattern "Scoperto pari al X% minimo di €.YYY" → scrivi "X% min. €YYY"
   - Pattern "scoperto del X% con un minimo non indennizzabile pari a € YYY" → "X% min. €YYY"
   - Pattern "X% con il minimo di euro YYY" → "X% min. €YYY"
   - Terremoto: tipicamente "10% min. €10.000 per abitazione; 10% min. €3.000 per contenuto"
   - Alluvione/Allagamento: cerca minimi separati per abitazione e contenuto
   - Furto dipendenze: tipicamente "10% min. €250"
   POLIZZE INFORTUNI — RIMBORSO SPESE MEDICHE (CRITICO):
   - Cerca nella sezione "TABELLA RIASSUNTIVA" o nelle condizioni del "Rimborso spese mediche" la riga con "Scoperto" o "%"
   - Pattern specifico: "Scoperto del 20% con il minimo di € 75" oppure "scoperto 20% min €75" → scrivi scoperto="20% min. €75" sulla garanzia "Rimborso spese mediche"
   - Cerca anche: "20%", "€ 75", "euro 75" vicino a "spese mediche", "rimborso", "scoperto"
   - Se trovi qualsiasi % di scoperto su una garanzia infortuni, aggiorna il campo scoperto di quella garanzia
   Aggiorna il campo "scoperto" con il valore COMPLETO includendo il minimo in €.

**AREA 4 — FRANCHIGIE IN GIORNI (solo polizze infortuni):**
CRITICO — cerca nelle sezioni "TABELLA RIASSUNTIVA", "Diaria per inabilità temporanea", "franchigie" franchigie espresse in giorni:
   - Cerca la riga relativa a "Inabilità temporanea" o "Diaria" nella tabella riassuntiva
   - Pattern: "5 giorni se la diaria scelta è pari o inferiore a euro 50; 10 giorni se... superiore a euro 50 e non superiore a euro 80; 15 giorni se superiore a euro 80" → scrivi franchigia="5/10/15 giorni (in base alla diaria scelta)"
   - Pattern semplice: "franchigia di N giorni" → scrivi "N giorni"
   - Pattern garbled: "5 giorni 10 giorni 15 giorni" vicino a "diaria" o "inabilità" → scrivi "5/10/15 giorni (in base alla diaria scelta)"
   - Invalidità permanente grave / Rendita vitalizia: cerca "Franchigia 65%" o "65%" vicino a queste garanzie → scrivi franchigia="65%"
   Aggiorna il campo "franchigia" delle garanzie Diaria/Inabilità con questo valore.

Aggiorna SOLO i campi che trovi ESPLICITAMENTE nel testo — NON inventare o stimare valori.
Restituisci l'array COMPLETO delle garanzie aggiornato (incluse quelle già corrette).
Se una garanzia ha massimale "illimitato" o "nessun massimale", usa massimale="Illimitato" e massimale_num=0.

Per polizze CASA dove il massimale è la Somma Assicurata (variabile): usa massimale="Somma assicurata" e massimale_num=0, ma COMPLETA le note con tutti i sublimiti trovati.

Restituisci SOLO un JSON valido con questa struttura:
{{
  "garanzie": [ ... array completo aggiornato ... ],
  "premio": "importo trovato oppure null",
  "punti_di_forza": [ ... aggiornati con valori numerici concreti se disponibili ... ],
  "esclusioni": [ ... aggiornate se trovi info migliori ... ]
}}

Regole:
- massimale: riporta il valore ESATTO dal testo (es: "500.000 €", "2.500.000 €", "Somma assicurata")
- massimale_num: numero puro corrispondente (es: 500000, 2500000) — usa 0 per "Somma assicurata"
- scoperto: SEMPRE con il minimo in € quando presente (es: "10% min. €10.000") — non solo la percentuale
- note: per polizze casa deve contenere "Sublimiti: ..." con tutti i sottolimiti trovati
- Se un valore non è nel testo, lascia null/0 — MAI inventare
- Mantieni tutti gli altri campi invariati se non hai informazioni migliori
- punti_di_forza: aggiorna con valori concreti (es: "RC con massimale fino a €5.000.000", "Assistenza €250/intervento h24")
- esclusioni: MASSIMO 6, solo le più sorprendenti/rilevanti per un cliente medio — NON elencare esclusioni tecniche ovvie (guerra, nucleare, dolo). Scegli quelle che un cliente tipicamente non si aspetta.
- REGOLA ASSOLUTA SUL CAMPO NOTE E MASSIMALE: è VIETATO scrivere qualsiasi frase del tipo "verificare ...", "da verificare ...", "non dettagliato nel testo", "non riportato nel testo estratto", "vedere scheda di polizza", "vedere tipologia scelta in scheda", "vedere tabella sezione", "vedere condizioni di assicurazione", "presente nella tabella sezione X", "tipologia scelta in polizza", "in base alla tipologia scelta", "definita in polizza", "come da scheda", "indicato in posizione assicurativa", "indicato in scheda", "scoperto indicato in", "come da posizione", "convenuto nella scheda", "nella scheda di polizza", "non disponibili in questa parte", "non disponibile in questa parte", "dettagli nella sezione", "vedere la sezione", "nella sezione assistenza", "riportato nella sezione" — se non trovi il valore lascia null/0, non scrivere spiegazioni. Per garanzie con più opzioni di franchigia: scrivi la franchigia standard nel campo franchigia, le varianti nel campo note — MAI riferirsi alla scheda. I valori FISSI come €250/intervento assistenza, massimale RC €5.000.000, gioielli max €15.000 SONO nel testo originale — cerca nella sezione "Responsabilità Civile", "limite massimo di risarcimento", "tabella riassuntiva". Per la Somma Assicurata (sola eccezione) usa massimale="Somma assicurata" e note=null.
- ECCEZIONE CRITICA NOTE: RC e Tutela Legale hanno massimali FISSI — NON usare "Somma assicurata" per queste garanzie. Estrai il valore esatto (es: RC €5.000.000/sinistro). Per Assistenza cerca il limite per tipo di intervento (es: €250/evento) e scrivilo come "Sublimiti: ..."."""


def _score_chunk(text: str) -> int:
    """
    Calcola lo score di rilevanza assicurativa di un chunk (puro Python, veloce).
    Usato per filtrare i chunk da mandare all'AI: solo quelli con score > soglia.
    """
    KEYWORDS_HIGH = [
        'massimale', 'somma assicurata', 'limite di indennizzo', 'limite massimo',
        'capitale assicurato', 'limite per sinistro', 'indennizzo massimo',
        'responsabilità civile', 'tutela legale', 'tabella riassuntiva',
        'garanzie', 'copertura', 'assicurazione', 'polizza',
    ]
    KEYWORDS_MED = [
        'franchigia', 'scoperto', 'sublimite', 'sinistro', 'indennizzo',
        'incendio', 'furto', 'assistenza', 'infortunio', 'invalidità',
        'diaria', 'rimborso', 'decesso', 'morte', 'premio',
    ]
    MONEY_PAT = re.compile(r'(?:€\s*[\d\.]+|[\d\.]{4,}(?:,\d{2})?\s*€|\d+\.\d{3})')
    t = text.lower()
    score = sum(t.count(kw) * 3 for kw in KEYWORDS_HIGH)
    score += sum(t.count(kw) * 2 for kw in KEYWORDS_MED)
    score += len(MONEY_PAT.findall(text)) * 2
    return score


async def _extract_single_chunk(text_chunk: str, filename: str, chunk_info: str = "") -> dict:
    """Estrae dati strutturati da un singolo chunk di testo polizza."""
    prompt = _build_extraction_prompt(text_chunk, filename, chunk_info)
    msg = await call_claude(
        model=MODEL_TEXT,
        max_tokens=5000,
        messages=[{"role": "user", "content": prompt}]
    )
    raw = msg.content[0].text.strip()
    match = re.search(r'\{[\s\S]*\}', raw)
    if not match:
        logger.warning(f"[extract] JSON non trovato nel chunk '{chunk_info}' di '{filename}' — chunk ignorato")
        return {}
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError as e:
        logger.warning(f"[extract] JSON malformato nel chunk '{chunk_info}' di '{filename}': {e} — chunk ignorato")
        # Tentativo di recupero: tronca al punto di errore e riprova
        raw_truncated = match.group(0)[:e.pos].rsplit(',', 1)[0] + "\n}}"
        try:
            return json.loads(raw_truncated)
        except Exception:
            return {}


def _merge_extractions(results: list) -> dict:
    """
    Unisce i risultati di più estrazioni sullo stesso documento (da chunk diversi).
    Strategia: garanzie deduplicate per nome (preferisce record più completo);
    metadati dal primo chunk (intestazione sempre nel testo iniziale).
    """
    if not results:
        return {}
    if len(results) == 1:
        return results[0]

    merged = results[0].copy()

    # ── Garanzie: deduplicazione per nome, preferisce record con massimale_num > 0
    #    e poi quello con più campi non-null
    all_garanzie: dict = {}
    for r in results:
        for g in r.get("garanzie", []):
            nome = (g.get("nome") or "").strip()
            if not nome:
                continue
            if nome not in all_garanzie:
                all_garanzie[nome] = g
            else:
                existing = all_garanzie[nome]
                new_mass = g.get("massimale_num") or 0
                ex_mass = existing.get("massimale_num") or 0
                # Una garanzia BASE (presente=true, opzionale=false) è sempre preferita
                # a una garanzia OPZIONALE con lo stesso massimale_num.
                # Questo evita che "Incendio Extra" (opzionale) sovrascriva la base.
                g_is_base = g.get("presente", False) and not g.get("opzionale", False)
                ex_is_base = existing.get("presente", False) and not existing.get("opzionale", False)
                if new_mass > ex_mass:
                    all_garanzie[nome] = g
                elif new_mass == ex_mass:
                    if ex_is_base and not g_is_base:
                        pass  # mantieni existing (base batte opzionale)
                    elif g_is_base and not ex_is_base:
                        all_garanzie[nome] = g  # nuovo è base, sostituisce
                    elif sum(1 for v in g.values() if v not in (None, 0, "")) > \
                         sum(1 for v in existing.values() if v not in (None, 0, "")):
                        all_garanzie[nome] = g

    # Secondo passaggio: per ogni garanzia nel merged, arricchisci con dati
    # complementari da altri chunk (franchigia, note, scoperto) anche quando il
    # massimale coincide — non perdiamo informazioni preziose dai chunk successivi.
    all_garanzie_by_chunk: dict[str, list] = {}
    for r in results:
        for g in r.get("garanzie", []):
            nome = (g.get("nome") or "").strip()
            if not nome:
                continue
            all_garanzie_by_chunk.setdefault(nome, []).append(g)

    for nome, best_g in all_garanzie.items():
        for g in all_garanzie_by_chunk.get(nome, []):
            if g is best_g:
                continue
            # Integra franchigia/scoperto/note se nel best sono null
            if g.get("franchigia") and not best_g.get("franchigia"):
                best_g["franchigia"] = g["franchigia"]
            if g.get("scoperto") and not best_g.get("scoperto"):
                best_g["scoperto"] = g["scoperto"]
            if g.get("note") and (not best_g.get("note") or best_g["note"] in (None, "null", "")):
                best_g["note"] = g["note"]

    merged["garanzie"] = list(all_garanzie.values())

    # ── Punti di forza: unione senza duplicati (max 5)
    seen: set = set()
    pf_merged = []
    for r in results:
        for pf in r.get("punti_di_forza", []):
            if pf and pf not in seen:
                seen.add(pf)
                pf_merged.append(pf)
    merged["punti_di_forza"] = pf_merged[:5]

    # ── Esclusioni: unione senza duplicati (max 8)
    seen = set()
    excl_merged = []
    for r in results:
        for e in r.get("esclusioni", []):
            if e and e not in seen:
                seen.add(e)
                excl_merged.append(e)
    merged["esclusioni"] = excl_merged[:8]

    # ── Metadati testuali: dal primo chunk non-null
    for field in ["compagnia", "prodotto", "tipo", "premio", "consigliata_per"]:
        for r in results:
            val = r.get(field)
            if val and val != "null":
                merged[field] = val
                break

    return merged


def _sanitize_extraction(result: dict) -> dict:
    """
    Post-processing: rimuove frasi di rimando a documenti esterni dai campi
    massimale, franchigia, scoperto, note delle garanzie.
    Questo garantisce che frasi come "indicato in scheda di polizza",
    "convenuto nella scheda", "vedere sezione X" non compaiano mai nell'output,
    indipendentemente da cosa genera il modello.
    """
    # Pattern che indicano un rimando a un documento esterno — non un valore reale
    REFERENCE_PATTERNS = [
        re.compile(r'scheda\s+di\s+polizza', re.IGNORECASE),
        re.compile(r'posizione\s+assicurativa', re.IGNORECASE),
        re.compile(r'indicat[oa]\s+in\s+(?!polizza\b)', re.IGNORECASE),  # escludi "Indicato in Polizza" (massimale RC variabile legittimo)
        re.compile(r'convenuto\s+(nella|in)\s+scheda', re.IGNORECASE),
        re.compile(r'vedere\s+(la\s+)?sezione', re.IGNORECASE),
        re.compile(r'nella\s+sezione\s+assistenza', re.IGNORECASE),
        re.compile(r'non\s+disponibil[ei]\s+in\s+questa\s+parte', re.IGNORECASE),
        re.compile(r'dettagli\s+(limiti|nella)\s+sezione', re.IGNORECASE),
        re.compile(r'nella\s+tabella\s+sezione', re.IGNORECASE),
        re.compile(r'come\s+da\s+(scheda|posizione)', re.IGNORECASE),
        re.compile(r'definit[oa]\s+in\s+polizza', re.IGNORECASE),         # "definito in polizza" → rimando (diverso da "Indicato in Polizza")
        re.compile(r'riportat[oa]\s+nella\s+sezione', re.IGNORECASE),
        re.compile(r'verific[a-z]+\s+(nella|in|la)', re.IGNORECASE),
        re.compile(r'da\s+verificare', re.IGNORECASE),
        re.compile(r'non\s+riportat[oa]\s+nel\s+testo', re.IGNORECASE),
        re.compile(r'non\s+dettagliat[oa]\s+nel\s+testo', re.IGNORECASE),
        re.compile(r'\bda\s+scheda\b', re.IGNORECASE),                  # "limiti da scheda"
        re.compile(r'in\s+tabella\s+art', re.IGNORECASE),               # "in tabella art. 24"
        re.compile(r'da\s+estrarre\s+nella', re.IGNORECASE),            # "da estrarre nella parte"
        re.compile(r'limiti\s+specific[io]\s+in\s+tabella', re.IGNORECASE),
        re.compile(r'specifici?\s+nella\s+(sezione|tabella)', re.IGNORECASE),
        re.compile(r'massimal[ei]\s+in\s+tabella', re.IGNORECASE),
        re.compile(r'convenuto\s+(in|nella)\s+polizza', re.IGNORECASE),
        re.compile(r'riferimento.*art\.\s*\d', re.IGNORECASE),
        re.compile(r'art\.\s*\d+\.\d+.*p[g.]?\s*\d+', re.IGNORECASE),
        re.compile(r'vedere\s+sezione\s+infortuni', re.IGNORECASE),
        # Nuovi pattern scoperti nel test v2
        re.compile(r'non\s+disponibil[ei]\s+nel\s+testo\s+estratto', re.IGNORECASE),
        re.compile(r'presenti?\s+nelle?\s+tabelle?\s+della?\s+sezione', re.IGNORECASE),
        re.compile(r'sublimiti\s+specific[io]\s+presenti', re.IGNORECASE),
        re.compile(r'limiti\s+per\s+intervento\s+presenti', re.IGNORECASE),
        re.compile(r'come\s+da\s+sezione\s+furto', re.IGNORECASE),
        re.compile(r'da\s+tabella\s+sezione', re.IGNORECASE),
    ]

    FIELDS_TO_SANITIZE = ["massimale", "franchigia", "scoperto", "note"]

    def _contains_reference(value: str) -> bool:
        if not value or not isinstance(value, str):
            return False
        return any(p.search(value) for p in REFERENCE_PATTERNS)

    for g in result.get("garanzie", []):
        for field in FIELDS_TO_SANITIZE:
            val = g.get(field)
            if _contains_reference(val):
                logger.info(f"[sanitize] Rimosso valore di rimando nel campo '{field}': {val[:80]!r}")
                g[field] = None
                if field == "massimale":
                    g["massimale_num"] = 0

    return result


def _apply_citation_filter(result: dict) -> dict:
    """
    Filtra i valori estratti che non hanno una citazione testuale di supporto.
    CONSERVATIVO: applica il filtro SOLO se il modello ha esplicitamente restituito
    il campo *_cite con valore null — NON se il campo è assente.
    Questo evita di azzerare valori corretti estratti da modelli che non compilano
    sempre le citazioni.
    """
    for g in result.get("garanzie", []):
        # Solo se il campo _cite è PRESENTE ed è esplicitamente null
        # (il modello l'ha visto e ha detto "non ho trovato la fonte")
        if "massimale_cite" in g and g["massimale_cite"] is None:
            if g.get("massimale_num", 0) > 0:
                logger.info(f"[cite] massimale ESPLICITAMENTE senza fonte: {g.get('nome')} → azzerato")
                g["massimale"] = None
                g["massimale_num"] = 0

        if "note_cite" in g and g["note_cite"] is None:
            note = g.get("note") or ""
            if "Sublimiti" in note:
                logger.info(f"[cite] note/sublimiti ESPLICITAMENTE senza fonte: {g.get('nome')} → azzerati")
                g["note"] = None

        if "scoperto_cite" in g and g["scoperto_cite"] is None:
            if g.get("scoperto"):
                logger.info(f"[cite] scoperto ESPLICITAMENTE senza fonte: {g.get('nome')} → azzerato")
                g["scoperto"] = None

        if "franchigia_cite" in g and g["franchigia_cite"] is None:
            franchigia = g.get("franchigia") or ""
            if "giorni" in franchigia.lower():
                logger.info(f"[cite] franchigia giorni ESPLICITAMENTE senza fonte: {g.get('nome')} → azzerata")
                g["franchigia"] = None

    # Rimuovi i campi _cite dall'output finale
    for g in result.get("garanzie", []):
        for field in ["massimale_cite", "note_cite", "scoperto_cite", "franchigia_cite"]:
            g.pop(field, None)

    return result


# ══════════════════════════════════════════════════════════════════════════════
# ── V2 — NATIVE PDF + TOOL USE ────────────────────────────────────────────────
# Architettura v2: Claude legge il PDF nativo (visivamente, tabelle incluse)
# e usa tool_use per garantire JSON strutturato senza errori di parsing.
# ══════════════════════════════════════════════════════════════════════════════

class ExtractRequestV2(BaseModel):
    pdf_base64: str   # PDF codificato in base64
    filename: str


# Schema tool use: garantisce output JSON valido che rispetta esattamente la struttura
EXTRACTION_TOOL_V2 = {
    "name": "extract_policy_data",
    "description": "Estrae la struttura completa di una polizza assicurativa italiana dal documento PDF. Leggi tabelle, DIP, schede tecniche e condizioni generali con massima precisione.",
    "input_schema": {
        "type": "object",
        "properties": {
            "compagnia":  {"type": ["string", "null"], "description": "Nome della compagnia assicuratrice"},
            "prodotto":   {"type": ["string", "null"], "description": "Nome commerciale del prodotto"},
            "tipo": {
                "type": "string",
                "enum": ["RC Auto", "Casa", "Vita", "Infortuni", "Salute", "Multirischio", "Risparmio", "altro"],
                "description": "Categoria principale della polizza"
            },
            "premio": {"type": ["string", "null"], "description": "Importo e periodicità del premio, null se non trovato"},
            "garanzie": {
                "type": "array",
                "description": "Lista completa di tutte le garanzie presenti o opzionali nella polizza",
                "items": {
                    "type": "object",
                    "properties": {
                        "categoria": {
                            "type": "string",
                            "enum": ["Danni alla proprietà", "Responsabilità Civile", "Infortuni",
                                     "Salute e Malattia", "Assistenza", "Tutela Legale",
                                     "Vita e Risparmio", "Veicoli", "Altro"]
                        },
                        "nome":        {"type": "string", "description": "Nome normalizzato dalla tassonomia garanzie"},
                        "presente":    {"type": "boolean", "description": "true se inclusa nel pacchetto base"},
                        "opzionale":   {"type": "boolean", "description": "true se acquistabile come supplemento a pagamento"},
                        "massimale":   {"type": ["string", "null"], "description": "Es: '5.000.000 €' o 'Somma assicurata' o null"},
                        "massimale_num": {"type": "number",  "description": "Valore numerico puro, 0 per SA/null"},
                        "franchigia":  {"type": ["string", "null"], "description": "Es: '250 €' o '5%' o '5/10/15 giorni' o null"},
                        "scoperto":    {"type": ["string", "null"], "description": "Es: '10% min. €250' — includi SEMPRE il minimo in €"},
                        "note":        {"type": ["string", "null"], "description": "Sublimiti e dettagli: 'Sublimiti: voce max €X | voce max €Y'"}
                    },
                    "required": ["nome", "categoria", "presente", "opzionale", "massimale_num"]
                }
            },
            "punti_di_forza": {
                "type": "array", "items": {"type": "string"},
                "description": "Max 5 punti di forza concreti con valori numerici"
            },
            "esclusioni": {
                "type": "array", "items": {"type": "string"},
                "description": "Max 6 esclusioni rilevanti e sorprendenti per il cliente"
            },
            "consigliata_per": {"type": ["string", "null"], "description": "Profilo cliente ideale in 1 frase"}
        },
        "required": ["tipo", "garanzie"]
    }
}


def _check_pdf_limits(pdf_bytes: bytes) -> None:
    """
    Verifica che il PDF rientri nei limiti generosi (anti-abuso).
    Lancia HTTPException 413 con messaggio chiaro se troppo grande.
    Le polizze lunghe reali rientrano sempre in questi limiti.
    """
    size_mb = len(pdf_bytes) / (1024 * 1024)
    if len(pdf_bytes) > MAX_PDF_BYTES:
        raise HTTPException(
            413,
            f"PDF troppo grande ({size_mb:.1f} MB). Limite massimo {MAX_PDF_BYTES // (1024*1024)} MB. "
            f"Se è una polizza valida molto pesante, comprimi il PDF o contatta l'assistenza."
        )
    # Conteggio pagine "best-effort": molti PDF di polizza reali (protetti/criptati o
    # con strutture che pypdf non digerisce) possono far fallire il conteggio, ma Claude
    # li legge comunque a vista. NON blocchiamo l'estrazione in quel caso: il tetto sui
    # MB sopra è già la vera protezione anti-abuso.
    try:
        n_pages = len(PdfReader(io.BytesIO(pdf_bytes)).pages)
    except Exception:
        logger.warning("[pdf] conteggio pagine non riuscito — procedo comunque (cap MB già verificato)")
        return
    if n_pages > MAX_PDF_PAGES:
        raise HTTPException(
            413,
            f"PDF con troppe pagine ({n_pages}). Limite massimo {MAX_PDF_PAGES}. "
            f"Carica solo il documento di polizza (CGA/DIP), non allegati estranei."
        )


def _split_pdf_bytes(pdf_bytes: bytes, pages_per_chunk: int = 60) -> list[tuple[bytes, int, int, int]]:
    """
    Divide un PDF in chunk di N pagine per rispettare i limiti dell'API Claude.
    Restituisce lista di (chunk_bytes, page_start, page_end, total_pages).
    """
    reader = PdfReader(io.BytesIO(pdf_bytes))
    total = len(reader.pages)
    chunks = []
    for start in range(0, total, pages_per_chunk):
        end = min(start + pages_per_chunk, total)
        writer = PdfWriter()
        for i in range(start, end):
            writer.add_page(reader.pages[i])
        buf = io.BytesIO()
        writer.write(buf)
        chunks.append((buf.getvalue(), start, end, total))
    return chunks


async def _extract_pdf_chunk_native(chunk_bytes: bytes, page_start: int, page_end: int,
                                     total_pages: int, filename: str) -> dict:
    """
    Estrae garanzie da un chunk PDF usando Claude native PDF + tool use.
    Claude legge il PDF visivamente: tabelle, layout, formattazione sono preservati.
    Tool use garantisce JSON strutturato senza errori di parsing.
    """
    chunk_b64 = base64.b64encode(chunk_bytes).decode()
    chunk_info = f"pagine {page_start + 1}-{page_end} di {total_pages}"

    prompt = f"""Sei un esperto di polizze assicurative italiane. Analizza questo PDF (file: {filename}, {chunk_info}).

{TASSONOMIA_GARANZIE}
{TASSONOMIA_CATEGORIE}

Estrai TUTTE le garanzie presenti usando la funzione extract_policy_data.

REGOLE CRITICHE:
— POLIZZE CASA/MULTIRISCHIO: massimale principale (Incendio, Furto) = "Somma assicurata". Estrai TUTTI i sublimiti nel campo note: "Sublimiti: voce max €X | voce max €Y"
— RC e Tutela Legale hanno di norma massimali FISSI nel testo (es: €5.000.000/sinistro). Se però il testo dice "massimale indicato in Polizza" o "come da Polizza", usa massimale="Indicato in Polizza" e massimale_num=0 — NON inventare una cifra.
— ASSISTENZA CASA: cerca negli articoli PER TIPO (es: "Invio idraulico", "Invio elettricista", "Invio fabbro", "Spese di albergo") il limite ESATTO per tipo di servizio. Attenzione: il limite alloggio/hotel (tipicamente €300/evento) È DIVERSO dal limite artigiani (tipicamente €250/evento). Pattern Unipol: "massimo complessivo di €X per evento, con un massimo di €Y per artigiano" → usa €Y come sub per ciascun artigiano. NON usare il valore dell'alloggio per gli artigiani. Scrivi in note: "Sublimiti: Idraulico/Elettricista/Fabbro max €X/evento | Alloggio max €W/evento | ..."
— POLIZZE INFORTUNI — "MORTE DA INFORTUNI" (o "Decesso da infortuni"): alcuni prodotti (es. Tandem) usano "Morte" invece di "Decesso". Mappala SEMPRE alla tassonomia come "Decesso da infortuni".
— POLIZZE INFORTUNI: massimale = "Somma assicurata". Leggi la TABELLA RIASSUNTIVA DI LIMITI per scoperti (es: "20% min. €75") e franchigie in giorni (es: "5/10/15 giorni in base alla diaria scelta")
— scoperto: includi SEMPRE il minimo in € (es: "10% min. €250", non solo "10%")
— esclusioni: MAX 6, solo le più sorprendenti/rilevanti per un cliente normale
— opzionale=true per garanzie acquistabili a pagamento, presente=false se assente dalla base
— NON inventare valori: se non trovi una cifra specifica, usa null/0"""

    try:
        msg = await call_claude(
            model=MODEL_VISION,
            max_tokens=8192,
            tools=[EXTRACTION_TOOL_V2],
            tool_choice={"type": "tool", "name": "extract_policy_data"},
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {
                            "type": "base64",
                            "media_type": "application/pdf",
                            "data": chunk_b64
                        }
                    },
                    {
                        "type": "text",
                        "text": prompt
                    }
                ]
            }]
        )
        if msg.stop_reason == "max_tokens":
            logger.warning(f"[extract-v2] TRONCATO (max_tokens) — alcuni dati potrebbero mancare")
        for block in msg.content:
            if block.type == "tool_use":
                return block.input
        logger.warning(f"[v2] nessun tool_use nella risposta per chunk {chunk_info} di '{filename}'")
        return {}
    except Exception as e:
        logger.error(f"[v2] errore estrazione chunk {chunk_info} di '{filename}': {e}")
        return {}


@app.post("/api/extract-stream-v2")
async def extract_policy_stream_v2(req: ExtractRequestV2):
    """
    V2 — Estrazione con native PDF + tool use.
    Invia eventi SSE progress/result come il v1.
    """
    try:
        pdf_bytes = base64.b64decode(req.pdf_base64)
    except Exception:
        raise HTTPException(400, "pdf_base64 non valido")

    if len(pdf_bytes) < 100:
        raise HTTPException(400, "PDF troppo piccolo o vuoto")
    _check_pdf_limits(pdf_bytes)

    async def generate():
        queue: asyncio.Queue = asyncio.Queue()

        async def do_extract():
            try:
                # Cache check
                cache_key = _cache_key(req.pdf_base64[:2000] + str(len(pdf_bytes)))
                if cache_key in _extraction_cache:
                    logger.info(f"[v2 stream] '{req.filename}' — cache hit")
                    await queue.put({"type": "progress", "step": "Risultato dalla cache...", "pct": 95})
                    await queue.put({"type": "result", "data": _extraction_cache[cache_key]})
                    return

                chunks = _split_pdf_bytes(pdf_bytes, pages_per_chunk=60)
                total = len(chunks)
                logger.info(f"[v2 stream] '{req.filename}' → {total} chunk(s) PDF, {len(pdf_bytes)//1024}KB")
                await queue.put({"type": "progress", "step": f"Lettura PDF ({total} sezioni, {len(pdf_bytes)//1024}KB)...", "pct": 5})

                # Processa tutti i chunk in parallelo
                results = await asyncio.gather(*[
                    _extract_pdf_chunk_native(chunk_b, p_start, p_end, p_tot, req.filename)
                    for chunk_b, p_start, p_end, p_tot in chunks
                ])
                await queue.put({"type": "progress", "step": "Merge risultati...", "pct": 80})

                # Filtra chunk vuoti e merge
                results = [r for r in results if r]
                if not results:
                    await queue.put({"type": "error", "message": "Nessun dato estratto dal PDF"})
                    return

                result = _merge_extractions(results) if len(results) > 1 else results[0]
                await queue.put({"type": "progress", "step": "Pulizia e verifica...", "pct": 92})

                result = _sanitize_extraction(result)
                _extraction_cache[cache_key] = result
                await queue.put({"type": "result", "data": result})

            except Exception as e:
                logger.error(f"[v2 stream] errore '{req.filename}': {e}")
                await queue.put({"type": "error", "message": str(e) or "Errore durante l'analisi"})

        task = asyncio.create_task(do_extract())
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=3.0)
                    yield f"data: {json.dumps(msg, ensure_ascii=False)}\n\n"
                    if msg["type"] in ("result", "error"):
                        break
                except asyncio.TimeoutError:
                    yield 'data: {"type":"ping"}\n\n'
        finally:
            if not task.done():
                task.cancel()

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── FINE V2 ───────────────────────────────────────────────────────────────────

# ── ENDPOINTS ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "polizza-facile"}

@app.get("/api/qdrant-test")
async def qdrant_test():
    """Test connessione Qdrant in tempo reale — mostra errore esatto."""
    if not QDRANT_URL:
        return {"error": "QDRANT_URL non configurato"}
    results = {}
    try:
        async with httpx.AsyncClient(timeout=15.0) as http:
            url = f"{QDRANT_URL}/collections"
            results["url_called"] = url
            results["api_key_length"] = len(QDRANT_API_KEY)
            results["api_key_prefix"] = QDRANT_API_KEY[:8] + "..." if QDRANT_API_KEY else "VUOTA"
            r = await http.get(url, headers=_qh())
            results["status_code"] = r.status_code
            results["response_text"] = r.text[:500]
    except httpx.ConnectError as e:
        results["error_type"] = "ConnectError"
        results["error"] = str(e)
    except httpx.TimeoutException as e:
        results["error_type"] = "Timeout"
        results["error"] = str(e)
    except Exception as e:
        results["error_type"] = type(e).__name__
        results["error"] = str(e)
    return results


@app.get("/api/debug")
async def debug():
    """Diagnostica stato connessione Qdrant."""
    info: dict = {
        "qdrant_url_configured": bool(QDRANT_URL),
        "qdrant_ok": _qdrant_ok,
        "collection": QDRANT_COLLECTION,
    }
    if QDRANT_URL and _qdrant_ok:
        try:
            async with httpx.AsyncClient(timeout=5.0) as http:
                r = await http.get(
                    f"{QDRANT_URL}/collections/{QDRANT_COLLECTION}",
                    headers=_qh()
                )
                d = r.json()
                info["points_count"] = d.get("result", {}).get("points_count", 0)
                info["status"] = "ok"
        except Exception as e:
            info["live_check_error"] = str(e)
    elif QDRANT_URL:
        info["reason"] = "Connessione Qdrant fallita al startup — vedi log Railway per dettagli"
    else:
        info["reason"] = "QDRANT_URL non configurato"
    return info

@app.get("/", response_class=HTMLResponse)
async def serve_root():
    """Backend API. Il frontend è servito separatamente (Vercel)."""
    return HTMLResponse(
        content="<!doctype html><meta charset='utf-8'>"
                "<title>Polizza Facile API</title>"
                "<body style='font-family:system-ui;padding:40px;color:#0F2741'>"
                "<h1>Polizza Facile — API</h1>"
                "<p>Servizio attivo. L'applicazione si usa dal sito ufficiale.</p>"
                "</body>",
        status_code=200,
    )


def _build_sequential_chunks(text: str, chunk_size: int, overlap: int) -> list[tuple[str, str]]:
    """
    Divide il testo in chunk sequenziali sovrapposti che coprono TUTTO il documento.
    Nessun limite al numero di chunk — legge ogni parte del testo.
    Restituisce lista di (testo_chunk, descrizione).
    """
    total_len = len(text)
    chunks = []
    start = 0
    while start < total_len:
        end = min(start + chunk_size, total_len)
        chunks.append(text[start:end])
        if end == total_len:
            break
        start += chunk_size - overlap

    total = len(chunks)
    return [(chunks[i], f"parte {i+1} di {total}") for i in range(total)]


async def _extract_all_chunks(chunks: list[tuple[str, str]], filename: str, batch_size: int = 8) -> list:
    """
    Estrae dati da tutti i chunk in batch paralleli per evitare di
    sovraccaricare l'API su documenti molto grandi.
    """
    all_results = []
    for i in range(0, len(chunks), batch_size):
        batch = chunks[i:i + batch_size]
        batch_results = await asyncio.gather(*[
            _extract_single_chunk(chunk_text, filename, chunk_info)
            for chunk_text, chunk_info in batch
        ])
        all_results.extend(batch_results)
    return all_results


def _extract_dense_sections(text: str, max_chars: int = 160_000) -> str:
    """
    Trova le sezioni del documento più ricche di dati numerici (massimali, tabelle, franchigie).
    Per ogni paragrafo calcola uno score basato su keyword assicurative e valori Euro.
    Include un "context window" di 12 paragrafi dopo ogni sezione critica (RC, tabelle riassuntive)
    per catturare le righe-dati che seguono le intestazioni di sezione.
    Restituisce le sezioni più dense fino a max_chars, mantenendo l'ordine originale.
    """
    KEYWORDS_HIGH = [
        'massimale', 'massimali', 'somma assicurata', 'somme assicurate',
        'limite di indennizzo', 'limite massimo', 'indennizzo massimo',
        'capitale assicurato', 'capitali assicurati', 'limite per sinistro',
        'limite per evento', 'DIP', 'documento informativo precontrattuale',
        'limite massimo di risarcimento', 'massimale per sinistro',
        'tabella riassuntiva', 'riepilogo', 'riepilogativa',
    ]
    KEYWORDS_MED = [
        'franchigia', 'scoperto', 'limite minimo', 'soglia', 'scoperti',
        'condizioni specifiche', 'scheda tecnica', 'tabella', 'prospetto',
        'responsabilità civile', 'tutela legale', 'assistenza',
        'decesso', 'invalidità permanente', 'inabilità temporanea',
        'diaria', 'rendita vitalizia', 'rimborso spese',
    ]
    # Pattern force-include: intestazioni di sezioni critiche + righe specifiche di tabelle
    FORCE_INCLUDE_PATTERNS = [
        re.compile(r'responsabilit[àa]\s+civile', re.IGNORECASE),
        re.compile(r'tabella\s+riassuntiva', re.IGNORECASE),
        re.compile(r'limite\s+massimo\s+di\s+risarcimento', re.IGNORECASE),
        re.compile(r'limiti.*franchigie.*scoperti', re.IGNORECASE),
        re.compile(r'scoperto.*minim', re.IGNORECASE),            # "Scoperto X% con il minimo di €YYY"
        re.compile(r'franchigia.*giorni|giorni.*franchigia', re.IGNORECASE),  # franchigie in giorni
        re.compile(r'rimborso\s+spese\s+medich', re.IGNORECASE),  # sezione rimborso spese
        re.compile(r'tutela\s+legale', re.IGNORECASE),             # sezione tutela legale
        re.compile(r'assistenza\s+casa|pronto\s+intervento', re.IGNORECASE),
        re.compile(r'(?:idraulic|elettric|fabbr|vetrai|intervento\s+tecnic).*€\s*\d+|€\s*\d+.*(?:idraulic|elettric|fabbr|vetrai|per\s+intervento)', re.IGNORECASE),
        re.compile(r'\bdecesso\b', re.IGNORECASE),                         # "Decesso" generico
        re.compile(r'decesso\s+da\s+infortun', re.IGNORECASE),           # sezione decesso infortuni (esplicita)
        re.compile(r'morte\s+da\s+infortun', re.IGNORECASE),             # Tandem usa "Morte da infortuni" non "Decesso"
        re.compile(r'sintesi\s+dei\s+limiti', re.IGNORECASE),            # tabella sommario limiti assistenza
        re.compile(r'assistenza\s+casa\s+(base|plus)', re.IGNORECASE),   # Zurich: "Assistenza casa base/plus"
        re.compile(r'massimale\s+di\s+\d+\s*euro|fino\s+a\s+un\s+massimale', re.IGNORECASE),  # limiti assistenza espliciti
        re.compile(r'massimale\s+indicato\s+in\s+polizza', re.IGNORECASE),  # RC variabile (Zurich, ITAS)
        re.compile(r'invalidit[àa]\s+permanente', re.IGNORECASE),        # sezione IP
        re.compile(r'inabilit[àa]\s+temporanea', re.IGNORECASE),         # sezione inabilità
        re.compile(r'diaria\s+(da\s+)?ricovero', re.IGNORECASE),         # sezione diaria
        re.compile(r'rendita\s+vitalizia', re.IGNORECASE),               # rendita vitalizia
    ]

    # Pattern per valori monetari italiani: 500.000 € o € 1.000 o 2.500.000,00
    MONEY_PATTERN = re.compile(r'(?:€\s*[\d\.]+|[\d\.]{4,}(?:,\d{2})?\s*€|\d+\.\d{3})')

    paragraphs = re.split(r'\n{2,}', text)
    # scores[idx] = (score, para_text)  — dict per O(1) lookup nel context window
    scores: dict[int, tuple[int, str]] = {}

    # Fase 1: scoring base per ogni paragrafo
    for idx, para in enumerate(paragraphs):
        if len(para.strip()) < 20:
            continue
        para_lower = para.lower()
        score = 0
        for kw in KEYWORDS_HIGH:
            score += para_lower.count(kw.lower()) * 3
        for kw in KEYWORDS_MED:
            score += para_lower.count(kw.lower()) * 2
        score += len(MONEY_PATTERN.findall(para)) * 2  # ogni valore Euro +2 punti
        # Force-include sezioni critiche
        for pattern in FORCE_INCLUDE_PATTERNS:
            if pattern.search(para):
                score += 50  # garantisce la selezione
                break
        if score > 0:
            scores[idx] = (score, para)

    # Fase 2: context window attorno ai force-include (score≥50)
    # Le intestazioni di sezione (RC, TABELLA RIASSUNTIVA) si trovano in un paragrafo,
    # ma i valori reali (€5.000.000, scoperto 20% min €75, franchigia 5/10/15 giorni)
    # sono nei paragrafi SUCCESSIVI. Boostiamo i prossimi 12 paragrafi con score decrescente.
    force_include_indices = [idx for idx, (s, _) in scores.items() if s >= 50]
    for fi_idx in force_include_indices:
        for j in range(1, 13):  # prossimi 12 paragrafi come contesto
            ctx_idx = fi_idx + j
            if ctx_idx >= len(paragraphs):
                break
            para = paragraphs[ctx_idx]
            if len(para.strip()) < 10:
                continue
            ctx_boost = max(5, 42 - j * 4)  # 38, 34, 30, 26, 22, 18, 14, 10, 6, 5, 5, 5
            if ctx_idx in scores:
                old_s, old_p = scores[ctx_idx]
                scores[ctx_idx] = (old_s + ctx_boost, old_p)
            else:
                scores[ctx_idx] = (ctx_boost, para)

    # Ordina per score decrescente
    scored_list = sorted(scores.items(), key=lambda x: -x[1][0])

    # Raccoglie le sezioni migliori rispettando il budget di caratteri
    selected: list[tuple[int, str]] = []
    total = 0
    # Includi sempre i primi 30k chars (DIP e intestazione sempre all'inizio)
    header = text[:30_000]
    total += len(header)

    for orig_idx, (score, para) in scored_list:
        if total >= max_chars:
            break
        remaining = max_chars - total
        if len(para) > remaining:
            para = para[:remaining]
        selected.append((orig_idx, para))
        total += len(para)

    # Riordina per posizione originale nel documento e unisci
    selected.sort(key=lambda x: x[0])
    body = '\n\n'.join(p for _, p in selected)

    return header + "\n\n[... sezioni dense estratte ...]\n\n" + body


# Tool use per il refinement: garantisce JSON valido senza parsing manuale
REFINEMENT_TOOL = {
    "name": "update_policy_data",
    "description": "Aggiorna i valori mancanti nelle garanzie già estratte cercandoli nel testo della polizza.",
    "input_schema": {
        "type": "object",
        "properties": {
            "garanzie": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "nome":         {"type": "string"},
                        "massimale":    {"type": ["string", "null"]},
                        "massimale_num":{"type": "number"},
                        "franchigia":   {"type": ["string", "null"]},
                        "scoperto":     {"type": ["string", "null"]},
                        "note":         {"type": ["string", "null"]}
                    },
                    "required": ["nome", "massimale_num"]
                }
            },
            "premio":        {"type": ["string", "null"]},
            "punti_di_forza":{"type": "array", "items": {"type": "string"}},
            "esclusioni":    {"type": "array", "items": {"type": "string"}}
        },
        "required": ["garanzie"]
    }
}


async def _refine_with_opus(merged: dict, text: str, filename: str) -> dict:
    """
    Pass finale di raffinamento con tool use: arricchisce massimali, sublimiti e franchigie
    mancanti cercando nelle sezioni dense del documento.
    Tool use garantisce JSON valido senza parsing manuale — nessun rischio di crash.
    """
    missing = [g for g in merged.get("garanzie", []) if not g.get("massimale_num")]
    if not missing:
        logger.info(f"[refine] '{filename}' — tutti i massimali già presenti, skip refinement")
        return merged

    logger.info(f"[refine] '{filename}' — estrazione sezioni dense (doc: {len(text)} chars, missing: {len(missing)})")
    dense_text = _extract_dense_sections(text, max_chars=100_000)
    logger.info(f"[refine] '{filename}' — sezioni dense estratte: {len(dense_text)} chars")

    prompt = _build_refinement_prompt(merged, dense_text, filename)
    try:
        msg = await call_claude(
            model=MODEL_TEXT,
            max_tokens=5000,
            tools=[REFINEMENT_TOOL],
            tool_choice={"type": "tool", "name": "update_policy_data"},
            messages=[{"role": "user", "content": prompt}]
        )

        # Tool use: il risultato è già un dict valido — nessun json.loads necessario
        refined = None
        for block in msg.content:
            if block.type == "tool_use":
                refined = block.input
                break

        if not refined:
            logger.warning(f"[refine] tool_use non trovato per '{filename}' — uso merged originale")
            return merged

        # Applica gli aggiornamenti al merged originale
        if "garanzie" in refined:
            refined_map = {g.get("nome", ""): g for g in refined["garanzie"]}
            for g in merged["garanzie"]:
                nome = g.get("nome", "")
                if nome in refined_map:
                    r = refined_map[nome]
                    if r.get("massimale_num", 0) > g.get("massimale_num", 0):
                        g["massimale"] = r.get("massimale")
                        g["massimale_num"] = r.get("massimale_num", 0)
                    if r.get("franchigia") and not g.get("franchigia"):
                        g["franchigia"] = r.get("franchigia")
                    if r.get("scoperto") and not g.get("scoperto"):
                        g["scoperto"] = r.get("scoperto")
                    if r.get("note") and (not g.get("note") or g["note"] == "null"):
                        g["note"] = r.get("note")

        if refined.get("premio") and not merged.get("premio"):
            merged["premio"] = refined["premio"]
        if refined.get("punti_di_forza"):
            merged["punti_di_forza"] = refined["punti_di_forza"]
        if refined.get("esclusioni"):
            merged["esclusioni"] = refined["esclusioni"]

        missing_after = sum(1 for g in merged["garanzie"] if not g.get("massimale_num"))
        logger.info(f"[refine] '{filename}' — completato. Massimali mancanti: {len(missing)} → {missing_after}")
        return merged

    except Exception as e:
        logger.warning(f"[refine] Errore per '{filename}': {e} — uso merged originale")
        return merged


@app.post("/api/extract")
async def extract_policy(req: ExtractRequest):
    """
    Estrae struttura garanzie/franchigie/scoperti da testo di polizza.
    Pipeline in 3 fasi per massima accuratezza:
    1. Lettura completa del documento (tutti i chunk, nessun limite)
    2. Merge intelligente dei risultati
    3. Raffinamento con Opus per completare massimali e franchigie mancanti
    """
    text = req.text.strip() if req.text else ""
    if len(text) < 100:
        raise HTTPException(400, "Testo polizza troppo breve o vuoto")

    CHUNK_SIZE = 90_000  # caratteri per chunk (aumentato per meno chiamate AI)
    OVERLAP    =  4_000  # sovrapposizione tra chunk consecutivi
    BATCH_SIZE =     16  # chunk processati in parallelo

    # Cache: se lo stesso documento è già stato analizzato, restituisce subito il risultato
    cache_key = _cache_key(text)
    if cache_key in _extraction_cache:
        logger.info(f"[extract] '{req.filename}' — cache hit, skip estrazione")
        return _extraction_cache[cache_key]

    try:
        if len(text) <= CHUNK_SIZE:
            result = await _extract_single_chunk(text, req.filename)
        else:
            chunks = _build_sequential_chunks(text, CHUNK_SIZE, OVERLAP)
            total = len(chunks)
            logger.info(f"[extract] '{req.filename}' → {total} chunk(s) su {len(text)} chars")

            results = await _extract_all_chunks(chunks, req.filename, BATCH_SIZE)
            result = _merge_extractions(results)

        result = await _refine_with_opus(result, text, req.filename)
        result = _sanitize_extraction(result)

        _extraction_cache[cache_key] = result
        return result

    except HTTPException:
        raise
    except json.JSONDecodeError:
        logger.error("JSON parse error in /api/extract")
        raise HTTPException(500, "Formato dati non valido — riprova")
    except Exception as e:
        logger.error(f"Error in /api/extract: {e}")
        raise HTTPException(500, "Errore durante l'analisi della polizza")


@app.post("/api/extract-stream")
async def extract_policy_stream(req: ExtractRequest):
    """
    Versione streaming SSE di /api/extract.
    Invia ping ogni 3s per mantenere la connessione viva su Cloudflare/Railway.
    Invia eventi 'progress' durante l'elaborazione e 'result' alla fine.
    Elimina definitivamente il problema 'Failed to fetch' da timeout.
    """
    text = req.text.strip() if req.text else ""
    if len(text) < 100:
        raise HTTPException(400, "Testo polizza troppo breve o vuoto")

    CHUNK_SIZE = 90_000
    OVERLAP    =  4_000
    BATCH_SIZE =     16

    async def generate():
        queue: asyncio.Queue = asyncio.Queue()

        async def do_extract():
            try:
                # Cache hit: risultato immediato
                cache_key = _cache_key(text)
                if cache_key in _extraction_cache:
                    logger.info(f"[stream] '{req.filename}' — cache hit")
                    await queue.put({"type": "progress", "step": "Risultato dalla cache...", "pct": 95})
                    await queue.put({"type": "result", "data": _extraction_cache[cache_key]})
                    return

                if len(text) <= CHUNK_SIZE:
                    await queue.put({"type": "progress", "step": "Analisi documento...", "pct": 30})
                    result = await _extract_single_chunk(text, req.filename)
                else:
                    all_chunks = _build_sequential_chunks(text, CHUNK_SIZE, OVERLAP)
                    total_raw = len(all_chunks)

                    # Selective chunking: scorare tutti i chunk (Python puro, veloce)
                    # e mandare all'AI solo i più rilevanti + i primi 2 (header/DIP)
                    scored = sorted(
                        enumerate(all_chunks),
                        key=lambda x: _score_chunk(x[1][0]),
                        reverse=True
                    )
                    # Sempre includi i primi 3 chunk (intestazione, DIP) + top 19 per score (tot ~22)
                    keep_indices = set(range(min(3, total_raw)))
                    for idx, _ in scored[:19]:
                        keep_indices.add(idx)
                    chunks = [all_chunks[i] for i in sorted(keep_indices)]
                    total = len(chunks)
                    skipped = total_raw - total
                    logger.info(f"[stream] '{req.filename}' → {total}/{total_raw} chunk(s) selezionati ({skipped} saltati)")
                    await queue.put({"type": "progress", "step": f"Analisi {total} sezioni chiave su {total_raw}...", "pct": 5})

                    all_results = []
                    for i in range(0, total, BATCH_SIZE):
                        batch = chunks[i:i + BATCH_SIZE]
                        batch_results = await asyncio.gather(*[
                            _extract_single_chunk(chunk_text, req.filename, chunk_info)
                            for chunk_text, chunk_info in batch
                        ])
                        all_results.extend(batch_results)
                        pct = 5 + int(70 * len(all_results) / total)
                        await queue.put({
                            "type": "progress",
                            "step": f"Analisi sezioni ({len(all_results)}/{total})...",
                            "pct": pct
                        })

                    result = _merge_extractions(all_results)

                await queue.put({"type": "progress", "step": "Verifica massimali e sublimiti...", "pct": 82})
                result = await _refine_with_opus(result, text, req.filename)
                result = _sanitize_extraction(result)
                _extraction_cache[cache_key] = result  # salva in cache
                await queue.put({"type": "result", "data": result})

            except HTTPException as he:
                logger.error(f"[stream] HTTPException per '{req.filename}': {he.detail}")
                await queue.put({"type": "error", "message": str(he.detail) or "Errore AI"})
            except Exception as e:
                logger.error(f"[stream] Errore per '{req.filename}': {e}")
                await queue.put({"type": "error", "message": str(e) or "Errore durante l'analisi"})

        task = asyncio.create_task(do_extract())
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=3.0)
                    yield f"data: {json.dumps(msg, ensure_ascii=False)}\n\n"
                    if msg["type"] in ("result", "error"):
                        break
                except asyncio.TimeoutError:
                    # Heartbeat: mantiene viva la connessione Cloudflare/Railway
                    yield 'data: {"type":"ping"}\n\n'
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disabilita buffering nginx/Cloudflare
            "Connection":       "keep-alive",
        }
    )


@app.post("/api/raccomanda")
async def raccomanda(req: RaccomandaRequest):
    """Genera raccomandazioni assicurative personalizzate dal questionario."""
    if not req.risposte:
        raise HTTPException(400, "Risposte questionario vuote")

    profile = "\n".join([f"- {k}: {v}" for k, v in req.risposte.items()])

    prompt = f"""Sei un esperto consulente assicurativo italiano. Analizza il profilo di questo cliente e genera raccomandazioni assicurative personalizzate.

PROFILO CLIENTE:
<profilo>
{profile}
</profilo>

Rispondi SOLO con un oggetto JSON valido con questa struttura:
{{
  "sintesi_profilo": "2 frasi che descrivono il profilo e i principali bisogni assicurativi",
  "raccomandazioni": [
    {{
      "priorita": 1,
      "tipo": "Tipo polizza (es: Vita, Infortuni, Salute, RC Professionale, Casa, Multirischio...)",
      "urgenza": "alta",
      "motivo": "Perché questa copertura è importante per questo specifico cliente (2-3 frasi concrete)",
      "cosa_cercare": ["caratteristica chiave 1", "caratteristica chiave 2", "caratteristica chiave 3"],
      "budget_indicativo": "es: 25–50 €/mese"
    }}
  ],
  "gap_principali": ["gap critico 1", "gap critico 2", "gap critico 3"],
  "nota_consulente": "Consiglio operativo per l'agente in 1-2 frasi"
}}

Regole:
- 3–5 raccomandazioni ordinate per priorità (priorita: 1 = più urgente)
- urgenza può essere solo: alta, media, bassa
- Considera le polizze già esistenti per non duplicare coperture
- motivo e cosa_cercare devono essere specifici per questo profilo, non generici
- budget_indicativo: stima realistica per il mercato italiano"""

    try:
        msg = await call_claude(
            model=MODEL_FAST,
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = msg.content[0].text.strip()
        match = re.search(r'\{[\s\S]*\}', raw)
        if not match:
            raise HTTPException(500, "Risposta AI non valida")
        return json.loads(match.group(0))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in /api/raccomanda: {e}")
        raise HTTPException(500, "Errore nella generazione delle raccomandazioni")


@app.post("/api/match")
async def match_client_policies(req: MatchRequest):
    """Analisi incrociata cliente/polizze con punteggi di compatibilità."""
    if not req.client or not req.policies:
        raise HTTPException(400, "Cliente e almeno una polizza sono richiesti")

    answers = req.client.get("answers", {})
    recs = req.client.get("raccomandazioni", {})
    gaps = recs.get("gap_principali", []) if recs else []
    profile_lines = "\n".join([f"  - {k}: {v}" for k, v in answers.items()])
    gaps_text = "\n".join([f"  - {g}" for g in gaps]) if gaps else "  - Non disponibili"

    policies_text = ""
    for i, p in enumerate(req.policies):
        garanzie = p.get("garanzie", [])
        g_text = ", ".join([
            f"{g['nome']} (max: {g.get('massimale','N/D')}, fr: {g.get('franchigia','nessuna')})"
            for g in garanzie if g.get("presente")
        ])
        policies_text += f"""
Polizza {i+1}: {p.get('compagnia','?')} — {p.get('prodotto','?')}
  Tipo: {p.get('tipo','?')} | Premio: {p.get('premio','N/D')}
  Garanzie attive: {g_text or 'N/D'}
  Punti di forza: {', '.join(p.get('punti_di_forza',[]))}
  Consigliata per: {p.get('consigliata_per','N/D')}
"""

    feedback_text = ""
    if req.feedback_history:
        feedback_text = "\n\nESEMPI DA CASI PRECEDENTI SIMILI (usa per calibrare):\n"
        for fb in req.feedback_history[:5]:
            feedback_text += (
                f"  - Profilo simile ({fb.get('clientType','?')}): {fb.get('note','')}"
                f" → Polizza scelta: {fb.get('chosenPolicy','?')} | Rating: {fb.get('rating','?')}/5\n"
            )

    prompt = f"""Sei un esperto consulente assicurativo italiano di Polo Assicurativo Bassano.
Analizza la compatibilità tra il profilo di questo cliente e le polizze disponibili.

PROFILO CLIENTE — {req.client.get('nome','Cliente')}:
<profilo>
{profile_lines}
</profilo>

GAP ASSICURATIVI IDENTIFICATI:
{gaps_text}
{feedback_text}
POLIZZE DA VALUTARE:
<polizze>
{policies_text}
</polizze>

Restituisci SOLO un JSON valido con questa struttura:
{{
  "client_summary": "Sintesi del profilo e dei bisogni principali in 2 frasi",
  "gap_analysis": ["gap 1", "gap 2", "gap 3"],
  "policy_matches": [
    {{
      "policy_index": 0,
      "compatibility_score": 85,
      "budget_fit": "ottimo | buono | stretto | fuori budget",
      "gap_coverage": [
        {{"gap": "nome gap", "covered": true, "score": 90, "note": "spiegazione breve"}}
      ],
      "strengths": ["punto di forza 1 per questo cliente", "punto 2"],
      "weaknesses": ["lacuna 1 per questo cliente", "lacuna 2"],
      "verdict": "1 frase: perché conviene o no per questo cliente"
    }}
  ],
  "ranking": [0, 1, 2],
  "top_recommendation": "2-3 frasi: quale polizza consigliare e perché, riferendosi ai bisogni specifici",
  "agent_tip": "Consiglio pratico per l'agente su come presentare la proposta a questo cliente"
}}

Regole:
- compatibility_score: 0-100, quanto la polizza copre i bisogni di QUESTO specifico cliente
- gap_coverage: analizza ogni gap identificato contro le garanzie della polizza
- ranking: array di policy_index ordinati dal più al meno adatto (0 = primo in lista polizze)
- Sii concreto e specifico per questo profilo, non generico
- budget_fit: confronta il premio con il budget dichiarato dal cliente"""

    try:
        msg = await call_claude(
            model=MODEL_TEXT,
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = msg.content[0].text.strip()
        match = re.search(r'\{[\s\S]*\}', raw)
        if not match:
            raise HTTPException(500, "Risposta AI non valida")
        return json.loads(match.group(0))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in /api/match: {e}")
        raise HTTPException(500, "Errore durante l'analisi di compatibilità")


@app.post("/api/summary")
async def generate_summary(req: SummaryRequest):
    """Genera un riepilogo comparativo in italiano semplice."""
    if len(req.policies) < 2:
        raise HTTPException(400, "Servono almeno 2 polizze per il confronto")

    brief = "\n".join([
        f"{p.get('compagnia','?')} — {p.get('prodotto','?')} ({p.get('tipo','?')})\n"
        f"Premio: {p.get('premio','N/D')}\n"
        f"Garanzie: {len(p.get('garanzie',[]))} trovate\n"
        f"Punti forza: {', '.join(p.get('punti_di_forza',[]))}"
        for p in req.policies
    ])

    profile_hint = ""
    if req.client_profile:
        profile_hint = "\nPROFILO CLIENTE (personalizza il consiglio per lui):\n"
        profile_hint += "\n".join([f"- {k}: {v}" for k, v in req.client_profile.items()])

    prompt = f"""Sei un consulente assicurativo italiano. Confronta queste polizze e scrivi un paragrafo di 3-4 frasi in italiano chiaro, pensato per un cliente non esperto.{profile_hint}

POLIZZE:
{brief}

Evidenzia la differenza principale tra le polizze, quale offre la copertura più ampia e quando conviene scegliere l'una o l'altra. Sii diretto e pratico, evita il gergo tecnico. Se hai il profilo del cliente, adatta il consiglio alle sue esigenze specifiche.

Rispondi solo con il testo del paragrafo, nessun titolo o prefazione."""

    try:
        msg = await call_claude(
            model=MODEL_FAST,
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}]
        )
        return {"summary": msg.content[0].text.strip()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in /api/summary: {e}")
        raise HTTPException(500, "Errore nella generazione del riepilogo")


# ══════════════════════════════════════════════════════════════════════════════
# ── ESTRAZIONE PER SEZIONI (v3) ───────────────────────────────────────────────
# Pipeline parallela — non tocca nulla del vecchio codice.
# Organizza l'output per sezioni (come le vere CG) invece di lista piatta.
# Endpoint: POST /api/extract-sezioni  |  POST /api/extract-sezioni-stream
# ══════════════════════════════════════════════════════════════════════════════

# ── DIZIONARIO SINONIMI ───────────────────────────────────────────────────────
# Per ogni sezione standard, lista di nomi alternativi usati dalle varie compagnie.
# Il modello usa questo dizionario per normalizzare i nomi estratti.

SINONIMI_SEZIONI_CASA: dict[str, dict] = {
    "incendio": {
        "id": "incendio",
        "nome_standard": "Incendio e danni ai beni",
        "sinonimi": [
            "protezione casa", "sezione protezione casa", "danni diretti",
            "incendio e altri danni", "sezione incendio", "garanzia incendio",
            "incendio e danni ai beni", "incendio e danni alla proprietà",
            "danni all'abitazione", "garanzia incendio e danni",
        ],
        "sotto_garanzie": [
            "incendio_fulmine_scoppio", "eventi_atmosferici", "atti_vandalici",
            "danni_acqua", "rottura_lastre", "ricerca_guasto", "spese_demolizione",
        ],
    },
    "furto": {
        "id": "furto",
        "nome_standard": "Furto",
        "sinonimi": [
            "sezione furto", "rapina e furto", "furto del contenuto",
            "furto e rapina", "garanzia furto", "furto e scippo",
        ],
        "sotto_garanzie": [
            "furto", "rapina", "scippo", "gioielli_preziosi",
            "denaro_valori", "furto_fuori_casa",
        ],
    },
    "rc": {
        "id": "rc",
        "nome_standard": "Responsabilità civile",
        "sinonimi": [
            "rc capofamiglia", "rc vita privata", "rc fabbricato",
            "rc abitazione", "responsabilità civile verso terzi",
            "rc della vita privata", "responsabilità civile abitazione",
            "responsabilità civile vita privata e animali",
            "rc abitazione vita privata e animali domestici",
        ],
        "sotto_garanzie": [
            "vita_privata", "proprieta_fabbricato", "conduzione_alloggi",
            "figli_minori", "animali_domestici",
        ],
    },
    "assistenza": {
        "id": "assistenza",
        "nome_standard": "Assistenza casa",
        "sinonimi": [
            "pronto intervento", "assistenza domiciliare", "sezione assistenza",
            "assistenza casa base", "assistenza casa plus", "sezione assistenza casa",
        ],
        "sotto_garanzie": [
            "artigiani", "asciugatura", "vigilanza", "deposito_contenuto",
            "pernottamento", "rientro_anticipato",
        ],
    },
    "tutela_legale": {
        "id": "tutela_legale",
        "nome_standard": "Tutela legale",
        "sinonimi": [
            "tutela legale immobile", "tutela legale vita privata",
            "sezione tutela legale", "tutela legale e protezione digitale",
            "tutela legale per i veicoli", "art. 24", "art. 22",
            "tutela legale polizza casa", "tutela legale polizza",
        ],
        "sotto_garanzie": [],
    },
    "terremoto_alluvione": {
        "id": "terremoto_alluvione",
        "nome_standard": "Terremoto e alluvione",
        "sinonimi": [
            "terremoto", "alluvione", "eventi catastrofali", "sezione terremoto",
            "terremoto e alluvione", "catastrofi naturali", "sezione terremoto e alluvione",
            "alluvione e inondazione",
        ],
        "sotto_garanzie": ["terremoto", "alluvione", "inondazione", "allagamento"],
    },
    "fotovoltaico": {
        "id": "fotovoltaico",
        "nome_standard": "Impianto fotovoltaico",
        "sinonimi": [
            "sezione fotovoltaico", "impianto solare", "fotovoltaico",
            "impianto fotovoltaico danni diretti",
        ],
        "sotto_garanzie": [],
    },
}

SINONIMI_SEZIONI_INFORTUNI: dict[str, dict] = {
    "morte": {
        "id": "morte",
        "nome_standard": "Morte da infortuni",
        "sinonimi": [
            "decesso da infortuni", "morte da infortuni", "capitale caso morte",
            "caso morte", "morte", "7.1 morte da infortuni",
            "morte da infortunio", "7.1 morte da infortunio",
            "caso morte da infortuni", "decesso", "morte infortuni",
        ],
        "sotto_garanzie": [],
    },
    "ip_infortuni": {
        "id": "ip_infortuni",
        "nome_standard": "Invalidità permanente da infortuni",
        "sinonimi": [
            "ip da infortuni", "invalidità permanente", "ip infortuni",
            "capitale ip", "invalidità permanente da infortunio",
            "ip base", "invalidità permanente base da infortuni",
        ],
        "sotto_garanzie": [],
    },
    "ip_infortuni_grave": {
        "id": "ip_infortuni_grave",
        "nome_standard": "Invalidità permanente grave da infortuni",
        "sinonimi": [
            "invalidità permanente grave da infortuni", "ip grave", "ip grave da infortuni",
            "ip grave infortuni", "invalidità grave infortuni",
            "invalidità permanente grave infortuni", "capitale ip grave",
            "integrazione ip grave", "grande invalidità da infortuni",
            "invalidità permanente totale da infortuni",
        ],
        "sotto_garanzie": [],
    },
    "rss_infortuni": {
        "id": "rss_infortuni",
        "nome_standard": "Rimborso spese sanitarie da infortuni",
        "sinonimi": [
            "rimborso spese mediche da infortuni", "rimborso spese di cura da infortuni",
            "spese sanitarie da infortuni", "rss infortuni",
            "rimborso spese infortuni", "spese di cura infortuni",
            "rimborso spese mediche", "rimborso spese di cura",
        ],
        "sotto_garanzie": [],
    },
    "rss_malattia": {
        "id": "rss_malattia",
        "nome_standard": "Rimborso spese sanitarie da malattia",
        "sinonimi": [
            "rimborso spese mediche da malattia", "rimborso spese di cura da malattia",
            "spese sanitarie da malattia", "rss malattia",
            "rimborso spese malattia", "spese di cura malattia",
            "rimborso spese sanitarie malattia",
        ],
        "sotto_garanzie": [],
    },
    "diaria_gesso": {
        "id": "diaria_gesso",
        "nome_standard": "Diaria gesso / immobilizzazione",
        "sinonimi": [
            "diaria da immobilizzazione", "indennità gesso", "diaria ingessatura",
            "diaria immobilizzazione", "diaria da ingessatura",
        ],
        "sotto_garanzie": [],
    },
    "diaria_ricovero": {
        "id": "diaria_ricovero",
        "nome_standard": "Diaria ricovero",
        "sinonimi": [
            "diaria da ricovero", "indennità ricovero", "diaria ospedaliera",
            "diaria per ricovero", "diaria da ricovero completa",
            "diaria ricovero ospedaliero", "indennità di ricovero",
        ],
        "sotto_garanzie": [],
    },
    "diaria_post_ricovero": {
        "id": "diaria_post_ricovero",
        "nome_standard": "Diaria post ricovero",
        "sinonimi": [
            "diaria post ricovero", "diaria post-ricovero", "indennità post ricovero",
            "diaria convalescenza", "indennità convalescenza",
            "diaria post dimissione", "diaria post ospedalizzazione",
            "diaria da ricovero prolungato", "diaria ricovero prolungato",
            "ricovero prolungato", "diaria da convalescenza",
        ],
        "sotto_garanzie": [],
    },
    "diaria_inabilita": {
        "id": "diaria_inabilita",
        "nome_standard": "Diaria inabilità temporanea",
        "sinonimi": [
            "inabilità temporanea al lavoro", "diaria per inabilità",
            "indennità giornaliera", "ita", "diaria inabilità",
            "diaria per inabilità temporanea",
            "diaria inabilità temporanea da infortuni",
            "inabilità temporanea totale da infortuni",
        ],
        "sotto_garanzie": [],
    },
    "diaria_inabilita_malattia": {
        "id": "diaria_inabilita_malattia",
        "nome_standard": "Diaria inabilità temporanea da malattia",
        "sinonimi": [
            "diaria inabilità da malattia", "inabilità temporanea da malattia",
            "diaria per malattia", "indennità giornaliera da malattia",
            "diaria malattia", "ita malattia",
            "diaria inabilità temporanea da malattia",
        ],
        "sotto_garanzie": [],
    },
    "ip_malattia": {
        "id": "ip_malattia",
        "nome_standard": "Invalidità permanente da malattia",
        "sinonimi": [
            "ip da malattia", "invalidità da malattia", "ip malattia",
            "ip ictus/infarto", "invalidità permanente da malattia",
            "invalidità permanente grave da malattia",
            "invalidità permanente da ictus o infarto",
        ],
        "sotto_garanzie": [],
    },
    "rendita_vitalizia": {
        "id": "rendita_vitalizia",
        "nome_standard": "Rendita vitalizia da infortuni",
        "sinonimi": [
            "rendita vitalizia", "rendita vitalizia da infortuni",
            "rendita da infortuni", "rendita infortuni",
        ],
        "sotto_garanzie": [],
    },
    "rendita_malattia": {
        "id": "rendita_malattia",
        "nome_standard": "Rendita vitalizia da malattia",
        "sinonimi": [
            "rendita da malattia", "rendita vitalizia da malattia",
            "rendita malattia", "rendita da ictus/infarto",
        ],
        "sotto_garanzie": [],
    },
    "stato_comatoso": {
        "id": "stato_comatoso",
        "nome_standard": "Stato comatoso irreversibile",
        "sinonimi": [
            "stato comatoso irreversibile", "stato comatoso", "coma irreversibile",
            "stato vegetativo permanente", "coma persistente",
            "stato comatoso permanente",
        ],
        "sotto_garanzie": [],
    },
    "sostegno_protezione": {
        "id": "sostegno_protezione",
        "nome_standard": "Sostegno e protezione",
        "sinonimi": [
            "sostegno e protezione", "sostegno e sicurezza", "sostegno protezione",
            "indennizzo sostegno", "garanzia sostegno e protezione",
            "sostegno alla famiglia", "protezione famiglia", "pacchetto sostegno",
            "indennità sostegno e protezione",
        ],
        "sotto_garanzie": [],
    },
    "tutela_legale": {
        "id": "tutela_legale",
        "nome_standard": "Tutela legale",
        "sinonimi": [
            "tutela legale", "sezione tutela legale", "tutela legale infortuni",
            "tutela legale polizza infortuni", "tutela legale vita privata",
            "difesa legale", "assistenza legale",
        ],
        "sotto_garanzie": [],
    },
    "assistenza_sanitaria": {
        "id": "assistenza_sanitaria",
        "nome_standard": "Assistenza sanitaria",
        "sinonimi": [
            "assistenza sanitaria", "assistenza in viaggio", "assistenza infortuni",
            "sezione assistenza", "assistenza unisalute", "assistenza blue assistance",
            "garanzia assistenza", "assistenza per infortuni", "assistenza per infortunio",
            "prestazioni di assistenza", "assistenza domiciliare infortuni",
        ],
        "sotto_garanzie": [],
    },
}

# Indice inverso sinonimi → id sezione (per lookup veloce)
def _build_synonym_index(mapping: dict) -> dict[str, str]:
    idx = {}
    for section_id, data in mapping.items():
        idx[data["nome_standard"].lower()] = section_id
        for syn in data["sinonimi"]:
            idx[syn.lower()] = section_id
    return idx

_SYN_CASA = _build_synonym_index(SINONIMI_SEZIONI_CASA)
_SYN_INFORTUNI = _build_synonym_index(SINONIMI_SEZIONI_INFORTUNI)

# Ramo SALUTE — modello "per canale": ricovero/alta diagnostica/visite hanno valori
# diversi per struttura convenzionata, non convenzionata e SSN. Il canale è codificato
# nel nome standard della sezione, così la tabella confronto mostra una riga per canale.
SINONIMI_SEZIONI_SALUTE: dict[str, dict] = {
    "ricovero_conv": {
        "id": "ricovero_conv",
        "nome_standard": "Ricovero — strutture convenzionate",
        "sinonimi": [
            "ricovero in strutture convenzionate", "ricovero rete convenzionata",
            "ricovero convenzionato", "ricovero in équipe convenzionata",
            "ricovero con intervento convenzionato",
        ],
        "sotto_garanzie": [],
    },
    "ricovero_nonconv": {
        "id": "ricovero_nonconv",
        "nome_standard": "Ricovero — strutture non convenzionate",
        "sinonimi": [
            "ricovero in strutture non convenzionate", "ricovero fuori rete",
            "ricovero non convenzionato", "ricovero a rimborso", "ricovero regime rimborsuale",
        ],
        "sotto_garanzie": [],
    },
    "ricovero_ssn": {
        "id": "ricovero_ssn",
        "nome_standard": "Ricovero — SSN (indennità sostitutiva)",
        "sinonimi": [
            "ricovero a totale carico ssn", "ricovero servizio sanitario nazionale",
            "indennità sostitutiva", "diaria sostitutiva ricovero ssn", "ricovero ssn",
        ],
        "sotto_garanzie": [],
    },
    "pre_ricovero": {
        "id": "pre_ricovero",
        "nome_standard": "Spese pre-ricovero",
        "sinonimi": [
            "spese pre ricovero", "spese precedenti il ricovero", "pre ricovero",
            "accertamenti pre ricovero", "spese prima del ricovero",
        ],
        "sotto_garanzie": [],
    },
    "post_ricovero": {
        "id": "post_ricovero",
        "nome_standard": "Spese post-ricovero",
        "sinonimi": [
            "spese post ricovero", "spese successive al ricovero", "post ricovero",
            "spese dopo il ricovero", "cure post ricovero",
        ],
        "sotto_garanzie": [],
    },
    "parto": {
        "id": "parto",
        "nome_standard": "Parto",
        "sinonimi": [
            "parto", "parto cesareo", "parto naturale", "maternità", "gravidanza e parto",
        ],
        "sotto_garanzie": [],
    },
    "alta_diagnostica_conv": {
        "id": "alta_diagnostica_conv",
        "nome_standard": "Alta diagnostica — convenzionate",
        "sinonimi": [
            "alta diagnostica strutture convenzionate", "alta specializzazione convenzionata",
            "accertamenti diagnostici convenzionati", "alta diagnostica convenzionata",
        ],
        "sotto_garanzie": [],
    },
    "alta_diagnostica_nonconv": {
        "id": "alta_diagnostica_nonconv",
        "nome_standard": "Alta diagnostica — non convenzionate",
        "sinonimi": [
            "alta diagnostica strutture non convenzionate", "alta specializzazione non convenzionata",
            "alta diagnostica fuori rete", "alta diagnostica a rimborso",
        ],
        "sotto_garanzie": [],
    },
    "alta_diagnostica_ssn": {
        "id": "alta_diagnostica_ssn",
        "nome_standard": "Alta diagnostica — SSN",
        "sinonimi": [
            "alta diagnostica ssn", "alta diagnostica servizio sanitario nazionale",
            "alta diagnostica ticket ssn",
        ],
        "sotto_garanzie": [],
    },
    "visite_conv": {
        "id": "visite_conv",
        "nome_standard": "Visite specialistiche — convenzionate",
        "sinonimi": [
            "visite specialistiche convenzionate", "visite mediche specialistiche convenzionate",
            "visite in strutture convenzionate", "visite specialistiche in rete",
        ],
        "sotto_garanzie": [],
    },
    "visite_nonconv": {
        "id": "visite_nonconv",
        "nome_standard": "Visite specialistiche — non convenzionate",
        "sinonimi": [
            "visite specialistiche non convenzionate", "visite mediche non convenzionate",
            "visite fuori rete", "visite specialistiche a rimborso",
        ],
        "sotto_garanzie": [],
    },
    "visite_ssn": {
        "id": "visite_ssn",
        "nome_standard": "Visite specialistiche — SSN",
        "sinonimi": [
            "visite specialistiche ssn", "visite ticket ssn", "visite servizio sanitario nazionale",
        ],
        "sotto_garanzie": [],
    },
    "checkup": {
        "id": "checkup",
        "nome_standard": "Check-up / prevenzione",
        "sinonimi": [
            "check up", "check-up", "prevenzione", "pacchetto prevenzione",
            "visite di prevenzione", "controlli preventivi",
        ],
        "sotto_garanzie": [],
    },
    "prest_post_ricovero": {
        "id": "prest_post_ricovero",
        "nome_standard": "Prestazioni post ricovero (fisioterapia)",
        "sinonimi": [
            "prestazioni specifiche post ricovero", "trattamenti fisioterapici",
            "fisioterapia", "riabilitazione post ricovero", "cure riabilitative",
        ],
        "sotto_garanzie": [],
    },
    "massimale_annuo": {
        "id": "massimale_annuo",
        "nome_standard": "Massimale annuo",
        "sinonimi": [
            "massimale annuo", "massimale per annualità", "massimale complessivo annuo",
            "somma assicurata annua", "plafond annuo",
        ],
        "sotto_garanzie": [],
    },
    "assistenza_sanitaria": {
        "id": "assistenza_sanitaria",
        "nome_standard": "Assistenza sanitaria",
        "sinonimi": [
            "assistenza sanitaria", "assistenza medica", "consulenza medica h24",
            "assistenza in viaggio", "second opinion", "centrale operativa",
        ],
        "sotto_garanzie": [],
    },
    "tutela_legale": {
        "id": "tutela_legale",
        "nome_standard": "Tutela legale",
        "sinonimi": [
            "tutela legale", "difesa legale", "assistenza legale",
        ],
        "sotto_garanzie": [],
    },
}
_SYN_SALUTE = _build_synonym_index(SINONIMI_SEZIONI_SALUTE)

# Ramo RC AUTO / VEICOLI — la triade limite/scoperto/franchigia calza bene:
# RCA ha massimale fisso, kasko/furto hanno franchigie/scoperti, ecc. I sotto-limiti
# (km traino, giorni auto sostitutiva, capitali conducente) vanno nel campo "gz".
SINONIMI_SEZIONI_RCAUTO: dict[str, dict] = {
    "rca": {
        "id": "rca",
        "nome_standard": "Responsabilità Civile Auto (RCA)",
        "sinonimi": [
            "responsabilità civile auto", "rca", "rc auto", "rc autoveicoli",
            "responsabilità civile obbligatoria", "garanzia rca", "massimale rca",
        ],
        "sotto_garanzie": [],
    },
    "kasko": {
        "id": "kasko",
        "nome_standard": "Kasko / collisione",
        "sinonimi": [
            "kasko", "collisione", "danni al veicolo", "mini kasko", "kasko collisione",
            "garanzia kasko", "danni accidentali al veicolo",
        ],
        "sotto_garanzie": [],
    },
    "furto_incendio": {
        "id": "furto_incendio",
        "nome_standard": "Furto e incendio",
        "sinonimi": [
            "furto e incendio", "furto incendio", "incendio e furto", "furto",
            "incendio del veicolo", "furto del veicolo",
        ],
        "sotto_garanzie": [],
    },
    "eventi_naturali": {
        "id": "eventi_naturali",
        "nome_standard": "Eventi naturali",
        "sinonimi": [
            "eventi naturali", "eventi atmosferici", "calamità naturali",
            "grandine", "alluvione veicolo", "eventi socio-politici",
        ],
        "sotto_garanzie": [],
    },
    "atti_vandalici_auto": {
        "id": "atti_vandalici_auto",
        "nome_standard": "Atti vandalici",
        "sinonimi": [
            "atti vandalici", "vandalismo", "danni da atti vandalici",
            "eventi sociopolitici", "atti dolosi di terzi",
        ],
        "sotto_garanzie": [],
    },
    "cristalli_auto": {
        "id": "cristalli_auto",
        "nome_standard": "Cristalli",
        "sinonimi": [
            "cristalli", "rottura cristalli", "cristalli auto", "parabrezza",
            "vetri del veicolo", "garanzia cristalli",
        ],
        "sotto_garanzie": [],
    },
    "infortuni_conducente": {
        "id": "infortuni_conducente",
        "nome_standard": "Infortuni del conducente",
        "sinonimi": [
            "infortuni del conducente", "infortuni conducente", "conducente",
            "tutela del conducente", "infortuni alla guida", "guida sicura",
        ],
        "sotto_garanzie": [],
    },
    "assistenza_stradale": {
        "id": "assistenza_stradale",
        "nome_standard": "Assistenza stradale",
        "sinonimi": [
            "assistenza stradale", "soccorso stradale", "traino", "auto sostitutiva",
            "assistenza veicoli", "pronto intervento stradale",
        ],
        "sotto_garanzie": [],
    },
    "tutela_legale": {
        "id": "tutela_legale",
        "nome_standard": "Tutela legale",
        "sinonimi": [
            "tutela legale", "tutela legale auto", "difesa legale", "assistenza legale",
            "spese legali", "tutela giudiziaria",
        ],
        "sotto_garanzie": [],
    },
}
_SYN_RCAUTO = _build_synonym_index(SINONIMI_SEZIONI_RCAUTO)

# Ramo AZIENDALE (multirischio PMI). Property + RC + interruzione attività + cyber.
# I sotto-limiti (fabbricato/contenuto/macchinari/merci, ecc.) vanno nel campo "gz".
SINONIMI_SEZIONI_AZIENDALE: dict[str, dict] = {
    "danni_beni": {
        "id": "danni_beni",
        "nome_standard": "Danni ai beni (incendio fabbricato e contenuto)",
        "sinonimi": [
            "danni ai beni", "incendio", "incendio e altri eventi", "danni materiali",
            "fabbricato e contenuto", "incendio fabbricato", "property",
            "incendio all risks", "all risks", "danni ai beni all risks",
        ],
        "sotto_garanzie": [],
    },
    "furto_aziendale": {
        "id": "furto_aziendale",
        "nome_standard": "Furto",
        "sinonimi": [
            "furto", "furto e rapina", "furto contenuto", "furto aziendale",
            "furto a primo rischio assoluto", "rapina",
        ],
        "sotto_garanzie": [],
    },
    "fenomeno_elettrico": {
        "id": "fenomeno_elettrico",
        "nome_standard": "Fenomeno elettrico/elettronico e guasti",
        "sinonimi": [
            "fenomeno elettrico", "danni elettrici", "elettronica e guasti",
            "guasti macchine", "guasti ai macchinari", "danni da fenomeno elettrico",
            "apparecchiature elettroniche",
        ],
        "sotto_garanzie": [],
    },
    "eventi_catastrofali": {
        "id": "eventi_catastrofali",
        "nome_standard": "Eventi catastrofali (terremoto/alluvione)",
        "sinonimi": [
            "eventi catastrofali", "terremoto", "alluvione", "catastrofi naturali",
            "terremoto e alluvione", "calamità naturali", "inondazione e allagamento",
        ],
        "sotto_garanzie": [],
    },
    "rct": {
        "id": "rct",
        "nome_standard": "Responsabilità civile verso terzi (RCT)",
        "sinonimi": [
            "responsabilità civile verso terzi", "rct", "rc terzi", "rc verso terzi",
            "responsabilità civile", "rc generale", "rc dell'impresa",
        ],
        "sotto_garanzie": [],
    },
    "rco": {
        "id": "rco",
        "nome_standard": "RC prestatori di lavoro (RCO/RCI)",
        "sinonimi": [
            "rco", "rci", "rc prestatori di lavoro", "responsabilità civile prestatori",
            "rc verso prestatori di lavoro", "rc dipendenti", "rc operai",
        ],
        "sotto_garanzie": [],
    },
    "rc_prodotti": {
        "id": "rc_prodotti",
        "nome_standard": "RC da prodotto difettoso",
        "sinonimi": [
            "rc prodotti", "responsabilità civile prodotti", "rc da prodotto difettoso",
            "product liability", "rc prodotto", "danni da prodotto",
        ],
        "sotto_garanzie": [],
    },
    "protezione_reddito": {
        "id": "protezione_reddito",
        "nome_standard": "Protezione del reddito (interruzione attività)",
        "sinonimi": [
            "protezione del reddito", "interruzione attività", "interruzione di esercizio",
            "perdita di profitti", "business interruption", "danni indiretti",
            "perdita pigioni", "diaria giornaliera", "indennità giornaliera attività",
        ],
        "sotto_garanzie": [],
    },
    "tutela_legale": {
        "id": "tutela_legale",
        "nome_standard": "Tutela legale",
        "sinonimi": [
            "tutela legale", "tutela legale impresa", "difesa legale", "spese legali",
            "assistenza legale",
        ],
        "sotto_garanzie": [],
    },
    "assistenza": {
        "id": "assistenza",
        "nome_standard": "Assistenza",
        "sinonimi": [
            "assistenza", "assistenza impresa", "pronto intervento", "servizi di assistenza",
            "assistenza tecnica",
        ],
        "sotto_garanzie": [],
    },
    "protezione_digitale": {
        "id": "protezione_digitale",
        "nome_standard": "Protezione digitale (cyber)",
        "sinonimi": [
            "protezione digitale", "cyber", "cyber risk", "rischi informatici",
            "sicurezza informatica", "attacco informatico", "danni cyber",
            "assistenza informatica", "protezione dati", "cyber e dati",
            "protezione dati e reputazione on-line",
        ],
        "sotto_garanzie": [],
    },
}
_SYN_AZIENDALE = _build_synonym_index(SINONIMI_SEZIONI_AZIENDALE)


# ── TOOL USE SCHEMA PER SEZIONI ───────────────────────────────────────────────

def _sezione_schema(tipo_polizza: str) -> dict:
    """Tool use schema per estrazione a sezioni. Cambia in base al tipo polizza."""

    if tipo_polizza in ("Casa", "Multirischio"):
        sezioni_enum = [d["nome_standard"] for d in SINONIMI_SEZIONI_CASA.values()]
        sotto_garanzie_desc = """
Oggetto con le sotto-garanzie della sezione. Per INCENDIO: incendio_fulmine_scoppio, eventi_atmosferici,
atti_vandalici, danni_acqua, rottura_lastre, ricerca_guasto, spese_demolizione.
Per FURTO: furto, rapina, scippo, gioielli_preziosi, denaro_valori, furto_fuori_casa.
Per RC: vita_privata, proprieta_fabbricato, conduzione_alloggi, figli_minori, animali_domestici.
Per ASSISTENZA: artigiani, asciugatura, vigilanza, deposito_contenuto, pernottamento.
"""
    elif tipo_polizza == "Salute":
        sezioni_enum = [d["nome_standard"] for d in SINONIMI_SEZIONI_SALUTE.values()]
        sotto_garanzie_desc = """Oggetto con dettagli per canale, quando il documento li distingue.
Per le garanzie con più canali (ricovero, alta diagnostica, visite) NON usare questo campo: crea invece
una SEZIONE separata per canale (convenzionato / non convenzionato / SSN) usando gli id dedicati.
Lascia null se la garanzia non ha canali distinti."""
    elif tipo_polizza == "RC Auto":
        sezioni_enum = [d["nome_standard"] for d in SINONIMI_SEZIONI_RCAUTO.values()]
        sotto_garanzie_desc = """Oggetto con varianti della garanzia, se il documento le distingue (es. furto vs incendio
con franchigie diverse). Lascia null se non ci sono varianti. I sotto-limiti (km traino, giorni auto
sostitutiva, capitali morte/IP del conducente) vanno nel campo "gz" della sezione, non qui."""
    elif tipo_polizza == "Aziendale":
        sezioni_enum = [d["nome_standard"] for d in SINONIMI_SEZIONI_AZIENDALE.values()]
        sotto_garanzie_desc = """Non usare questo campo per i sotto-limiti: i sotto-limiti delle sezioni aziendali
(fabbricato, contenuto, macchinari, merci, ricorso terzi; valori in cassaforte; diaria/perdita pigioni per
l'interruzione attività) vanno nel campo "gz" della sezione. Lascia null."""
    else:  # Infortuni
        sezioni_enum = [d["nome_standard"] for d in SINONIMI_SEZIONI_INFORTUNI.values()]
        sotto_garanzie_desc = """Oggetto con varianti della sezione, quando il documento le distingue esplicitamente.
Per IP: {"base": true, "grave": true} se esistono due livelli (base e grave/≥soglia).
Per Diaria inabilità: {"da_infortuni": true, "da_malattia": true} se entrambe presenti.
Per Rimborso spese: {"da_infortuni": true, "da_malattia": true} se entrambe presenti.
Per Rendita: {"da_infortuni": true, "da_malattia": true} se entrambe presenti.
Lascia null se la sezione non ha varianti distinte."""

    # Campo garanzie_detail: solo per polizze Casa
    garanzie_detail_schema = None
    if tipo_polizza in ("Casa", "Multirischio"):
        garanzie_detail_schema = {
            "type": ["object", "null"],
            "description": """Per polizze Casa/Multirischio. Estrai sublimite (sub), scoperto (scop), franchigia (fra) per ogni sotto-garanzia.
Struttura richiesta:
{
  "incendio":   {"mass": "€ X", "gz": {"incendio_b": {"sub": null, "scop": null, "fra": "€ 250"}, "eventi_atm": {"sub": "€ 200.000", "scop": "10% min. €500", "fra": null}, ...}},
  "furto":      {"mass": "€ X", "gz": {"furto_b": {...}, "scippo": {...}, "guasti_ladri": {...}, "preziosi": {...}, "denaro": {...}, "oggetti_arte": {...}}},
  "rc":         {"mass": "€ X", "gz": {"rc_vita_privata": {"sub": "indicato in Polizza"}, "rc_conduzione": {...}, "rc_proprieta_fabbricati": {...}, "rc_animali": {...}, "rc_figli": {...}}},
  "cristalli":  {"mass": "€ X", "gz": {"crist_b": {...}, "crist_spec": {...}, "crist_san": {...}}} oppure null se sezione assente,
  "catastrofi": {"mass": "€ X", "gz": {"terremoto": {"scop": "10% min. €10.000"}, "allagamento": {...}, "alluvione": {...}, "inondazione": {...}, "esondazione": {...}}} oppure null se assenti,
  "assistenza": {"mass": "€ 250/evento", "gz": {"ass_idraul": {"sub": "€ 250", "scop": null, "fra": null}, "ass_elett": {"sub": "€ 250", "scop": null, "fra": null}, "ass_fabbro": {"sub": "€ 250", "scop": null, "fra": null}, "ass_allogg": {"sub": "€ X", "scop": null, "fra": null}, "ass_guard": {"sub": "€ X", "scop": null, "fra": null}}}
}
Regole valore garanzia:
— null: garanzia INCLUSA ma coperta fino alla Somma Assicurata senza sublimite specifico (verrà mostrata "S.A."); usa null anche per una garanzia esplicitamente esclusa.
— {"sub": null, "scop": null, "fra": null}: garanzia inclusa senza limiti specifici (equivalente a S.A.).
— {"opt": true}: garanzia OPZIONALE, coperta solo se si acquista un supplemento/garanzia aggiuntiva (NON inclusa nella base). IMPORTANTE: "opzionale" NON significa "senza valori" — DEVI comunque compilare sub/scop/fra del supplemento quando il documento li indica (li trovi tipicamente nelle tabelle "Garanzie Supplementari" con le colonne "Limiti/Sottolimiti" e "Franchigie/Scoperti", oltre che negli articoli e nel DIP). Es: {"opt": true, "fra": "€ 150/250/400"}, {"opt": true, "fra": "€ 250"}, {"opt": true, "sub": "€ 5.000", "scop": "10% min. €500"}. Una garanzia opzionale NON deve restare con scoperto/franchigia vuoti se il CGA li specifica per quel supplemento.
— valori: stringhe testuali come "€ 3.000", "10% min. €250", "5% del massimale"
— VALORI VARIABILI ("indicato in Polizza"): se un limite/scoperto/franchigia non è fissato nel CGA ma rimandato al contratto (es. "Scoperto indicato in Posizione assicurativa", "Franchigia indicata in Polizza", "massimale indicato in Polizza"), riporta testualmente "indicato in Polizza" in quel campo invece di lasciarlo null. Così è chiaro che la voce ESISTE ma il valore è personalizzato, e non sembra che manchi.
— SCOPERTI E FRANCHIGIE — CATTURALI DOVE SI APPLICANO DAVVERO: per ogni garanzia compila scop (scoperto, in %) e fra (franchigia, in cifra fissa) ogni volta che il documento prevede uno scoperto/franchigia ORDINARIO per quella garanzia. Cercali NON solo nell'articolo della singola garanzia ma anche negli articoli "Delimitazioni", "Franchigie e scoperti"/"Scoperti e franchigie", nelle tabelle riassuntive e nel frontespizio/DIP. Riporta il testo esatto (es. scop="10% min. €250", fra="€ 250").
— FRANCHIGIA/SCOPERTO DI GRUPPO O DI SEZIONE — PROPAGALI se ordinari: se una franchigia/scoperto è dichiarata per un INTERO gruppo di garanzie o per la sezione e vale in condizioni NORMALI (es. "per le garanzie a), b), c) l'Indennizzo è liquidato con una Franchigia di €250 per Sinistro"), applicala alle garanzie interessate — di norma la garanzia base (incendio_b, furto_b, ...) — invece di lasciare "—".
— NON FORZARE valori dove non si applicano: (1) uno scoperto/franchigia CONDIZIONATO, valido solo in circostanze particolari (es. "Scoperto 20% SE i mezzi di chiusura non sono conformi", "franchigia X se l'abitazione è disabitata da oltre 30 giorni"), NON è lo scoperto/franchigia ordinario della garanzia: lascia scop/fra a null e, se rilevante, segnala la circostanza tra le condizioni/esclusioni — NON metterlo come scop/fra della garanzia. (2) Una franchigia/scoperto che riguarda solo una voce di NICCHIA o una garanzia OPZIONALE a parte (es. franchigia €250 sul solo deturpamento/imbrattamento, o sull'Incendio Extra opzionale) NON va promossa alla garanzia base.
— "—" CORRETTO È MEGLIO DI UN VALORE FORZATO: lascia scop/fra a null (mostrato "—") quando per quella garanzia, in condizioni normali, il documento non prevede né scoperto né franchigia.
— SEZIONE NON PRESENTE NEL DOCUMENTO: se un'intera sezione (es. Responsabilità Civile, Tutela Legale) NON è descritta in questo documento perché è un modulo separato, OMETTI del tutto la chiave di sezione in garanzie_detail (non metterla, non usare null). null si usa solo a livello di singola sotto-garanzia.
— ASSISTENZA — regola critica: per ass_idraul/ass_elett/ass_fabbro il "sub" è il limite rimborsato per SINGOLO invio artigiano ("fino a un massimo di €X per evento/intervento"). Cerca ESATTAMENTE nell'articolo dedicato (es: "Art. X Invio idraulico", "Art. X Invio elettricista"). NON usare massimali di sezione generali o valori da tabelle riassuntive che potrebbero riferirsi ad altri servizi. Se non trovi il valore esplicito → {"sub": null, "scop": null, "fra": null}. NON inventare valori.
— ASSISTENZA — pattern "massimo complessivo + massimo per artigiano": se il testo dice "massimo complessivo di €X per evento, con un massimo di €Y per artigiano" → mass.assistenza="€Y/artigiano" (o "€X/evento complessivo"), ass_idraul.sub=ass_elett.sub=ass_fabbro.sub="€ Y". Il campo "mass" può riportare la struttura completa es: "€ 400/evento (max € 200/artigiano)".
— ASSISTENZA — alloggio vs artigiani: ass_allogg.sub È DIVERSO dai limiti artigiani. Il limite per albergo/pernottamento (tipicamente €300/evento) è SEPARATO e MAGGIORE del limite per artigiani (tipicamente €250/evento). NON usare il valore alloggio (€300) per gli artigiani.
— RC — rc_inquin: se il testo della sezione RC esclude ESPLICITAMENTE i danni da inquinamento (es: "non comprende i danni derivanti da inquinamento o contaminazione"), allora rc_inquin=null. Se non c'è esclusione esplicita → {"sub": null, "scop": null, "fra": null} (inclusa senza limiti specifici).
— CRISTALLI — la copertura per rottura di vetri/cristalli ("Vetri e cristalli", "rottura cristalli e lastre", "rottura lastre/specchi") è spesso una garanzia collocata DENTRO la sezione Incendio/Protezione Casa (es. articolo "Vetri e cristalli" nell'elenco delle opzioni a premio aggiuntivo), non una sezione autonoma. In quel caso popola COMUNQUE la chiave "cristalli": crist_b={"opt": true} se è un supplemento a pagamento (aggiungi sub/scop/fra se indicati, es. danni al contenuto max €3.000), oppure crist_b inclusa nella base ({"sub": ...} o {"sub": null, "scop": null, "fra": null}) se è compresa senza supplemento. Valorizza crist_spec (specchi/lastre) e crist_san (sanitari) SOLO se il testo li distingue esplicitamente, altrimenti ometti quelle sotto-garanzie. Includi la chiave "cristalli" ogni volta che il documento menziona la copertura per rottura di vetri/cristalli/specchi/lastre, anche come opzione; ometti la chiave "cristalli" SOLO se il documento non ne parla affatto.
— INCENDIO — demolizione (spese_demolizione): il sub va letto ESATTAMENTE come scritto nel testo. "30% dell'indennizzo" e "5% del massimale" sono VALORI DIVERSI e non intercambiabili. Copia il testo esatto (es: "30% dell'indennizzo", "20% dell'indennizzo max €30.000").
— INCENDIO — ricerca_guasto: il sublimite si trova NELL'ARTICOLO DEDICATO (es: "Art. X Ricerca del guasto"), tipicamente "5% del valore assicurato alla partita fabbricato con il massimo di €X". Riporta il massimale fisso come sub (es: "€ 2.500", non "€ 1.000" se il testo dice €2.500).
— INCENDIO — voci da includere nella sezione (NON tra le marginali): guasti_serramenti (danni ai serramenti/infissi da furto o atti vandalici), demolizione (spese di demolizione e sgombero), fotovoltaico (impianti fotovoltaici/pannelli solari). Sono garanzie importanti della sezione Incendio.
— ALL RISK vs RISCHI NOMINATI: nel campo top-level "forma_copertura" indica "All Risk" se la polizza copre TUTTI i danni tranne quelli esclusi (formula "all risks"/"tutti i rischi"), oppure "Rischi Nominati" se copre SOLO gli eventi elencati. Se non è chiaro → null.
— ALL RISK — copertura implicita: in una polizza ALL RISK, una garanzia property non esplicitamente esclusa è COMPRESA anche se non ha un articolo dedicato. In particolare i CRISTALLI: se non c'è un articolo "vetri/cristalli" ma la polizza è All Risk e non li esclude, popola crist_b = {"sub": null, "scop": null, "fra": null, "nome": "Rottura cristalli (compresa All Risk)"} invece di omettere la sezione.
— RC — VOCI DA ESTRARRE con i rispettivi massimali: rc_vita_privata (RC della vita privata, NON verso terzi generica), rc_conduzione (RC conduzione alloggi/locatario), rc_proprieta_fabbricati (RC proprietà del fabbricato), rc_animali (RC animali domestici), rc_figli (danni da figli minori). Per OGNI voce metti il massimale nel "sub" (es. "fino a €1.000.000" o "indicato in Polizza"). Per rc_figli: scrivi SEMPRE "indicato in Polizza" e aggiungi il massimale se esiste (es. "indicato in Polizza, max €500.000").
— CATASTROFI naturali: NON accorparle in una riga sola. Spezzale nella chiave "catastrofi" con voci separate: terremoto, allagamento, alluvione, inondazione, esondazione — ognuna con il suo scoperto/franchigia/limite. Se il documento le tratta insieme, replica lo stesso valore sulle voci presenti; ometti le voci non coperte.
— ETICHETTE LIMITI: distingui SEMPRE i sublimiti "complessivi" da quelli "per singolo oggetto". Es. Preziosi e collezioni → sub "fino a €15.000 complessivamente"; Quadri/tappeti/sculture → sub "€25.000 per singolo oggetto". Quando il limite è una percentuale, scrivilo come "fino al X% della SA" (es. "fino al 50% SA contenuto, max €15.000 complessivo").
IDs garanzie (usa esattamente questi):
  incendio:   incendio_b, eventi_atm, fenomeno_el, sparg_acqua, ricerca_guasto, atti_vandal, guasti_serramenti, demolizione, fotovoltaico
  furto:      furto_b, scippo, guasti_ladri, preziosi, denaro, oggetti_arte
  rc:         rc_vita_privata, rc_conduzione, rc_proprieta_fabbricati, rc_animali, rc_figli, rc_inquin, rc_incend, rc_cani
  cristalli:  crist_b, crist_spec, crist_san
  catastrofi: terremoto, allagamento, alluvione, inondazione, esondazione
  assistenza: ass_idraul, ass_elett, ass_fabbro, ass_allogg, ass_guard"""
        }

    properties = {
        "compagnia":  {"type": ["string", "null"]},
        "prodotto":   {"type": ["string", "null"]},
        "tipo":       {"type": "string", "enum": ["RC Auto", "Casa", "Vita", "Infortuni", "Salute", "Multirischio", "Aziendale", "Risparmio", "altro"]},
        "premio":     {"type": ["string", "null"]},
        "forma_copertura": {"type": ["string", "null"], "enum": ["All Risk", "Rischi Nominati", None], "description": "Solo per polizze a danni (Casa/Aziendale): 'All Risk' se copre tutti i danni tranne gli esclusi, 'Rischi Nominati' se copre solo gli eventi elencati. null se non applicabile o non chiaro."},
    }
    if garanzie_detail_schema:
        properties["garanzie_detail"] = garanzie_detail_schema

    return {
        "name": "extract_sezioni",
        "description": f"Estrae la struttura a sezioni di una polizza assicurativa italiana di tipo {tipo_polizza}.",
        "input_schema": {
            "type": "object",
            "properties": {
                **properties,
                "sezioni": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id":           {"type": "string", "description": "ID normalizzato (snake_case). CASA: incendio, furto, rc, assistenza, tutela_legale, terremoto_alluvione, fotovoltaico. INFORTUNI: morte, ip_infortuni, ip_infortuni_grave, rss_infortuni, rss_malattia, diaria_gesso, diaria_ricovero, diaria_post_ricovero, diaria_inabilita, diaria_inabilita_malattia, ip_malattia, rendita_vitalizia, rendita_malattia, stato_comatoso, sostegno_protezione, tutela_legale, assistenza_sanitaria. SALUTE: ricovero_conv, ricovero_nonconv, ricovero_ssn, pre_ricovero, post_ricovero, parto, alta_diagnostica_conv, alta_diagnostica_nonconv, alta_diagnostica_ssn, visite_conv, visite_nonconv, visite_ssn, checkup, prest_post_ricovero, massimale_annuo, assistenza_sanitaria, tutela_legale. RC AUTO: rca, kasko, furto_incendio, eventi_naturali, atti_vandalici_auto, cristalli_auto, infortuni_conducente, assistenza_stradale, tutela_legale. AZIENDALE: danni_beni, furto_aziendale, fenomeno_elettrico, eventi_catastrofali, rct, rco, rc_prodotti, protezione_reddito, tutela_legale, assistenza, protezione_digitale"},
                            "nome":         {"type": "string", "description": f"Nome NORMALIZZATO. Usa ESATTAMENTE uno di: {', '.join(sezioni_enum)}. NON inventare nomi diversi — usa i sinonimi per riconoscere la sezione, poi metti il nome standard."},
                            "inclusa":      {"type": "boolean", "description": "true se presente nel pacchetto base"},
                            "opzionale":    {"type": "boolean", "description": "true se acquistabile come extra, false se assente"},
                            "massimale":    {"type": ["string", "null"], "description": "Es: '5.000.000 €', 'Somma assicurata', 'Indicato in Polizza', null"},
                            "massimale_num":{"type": "number",  "description": "Valore numerico puro, 0 per SA/variabile"},
                            "franchigia":   {"type": ["string", "null"]},
                            "scoperto":     {"type": ["string", "null"], "description": "SEMPRE con minimo in € se presente: '10% min. €250'"},
                            "sublimiti":    {"type": ["string", "null"], "description": "Sublimiti chiave in formato: 'Gioielli max €15.000 | Valori max €2.500 | ...'"},
                            "sotto_garanzie": {
                                "type": ["object", "null"],
                                "description": sotto_garanzie_desc,
                                "additionalProperties": {"type": ["boolean", "string", "null"]}
                            },
                            "note": {"type": ["string", "null"], "description": "Info aggiuntive non coperte dagli altri campi"},
                            "gz": {"type": ["object", "null"], "additionalProperties": True, "description": "Sotto-garanzie / sotto-limiti STRUTTURATI di questa sezione (usalo per Infortuni e Salute). Ogni voce: chiave = id snake_case, valore = {\"nome\": etichetta leggibile, \"sub\": limite, \"scop\": scoperto %, \"fra\": franchigia, \"fonte\": rif., \"conf\": alta/media/bassa}. Es. per Rimborso spese: {\"protesi\": {\"nome\": \"Protesi anatomiche\", \"sub\": \"50% mass. max €5.000\"}, \"apparecchiature\": {\"nome\": \"Apparecchiature terapeutiche/ortopediche\", \"sub\": \"€2.500\"}, \"infermieristica\": {\"nome\": \"Assistenza infermieristica\", \"sub\": \"€50/gg x 90 gg\"}}. Spezza OGNI sotto-limite numerico in una voce con nome leggibile invece di lasciarlo solo nel testo. Usa lo STESSO nome per lo stesso concetto tra compagnie diverse. null se la sezione non ha sotto-limiti distinti."},
                            "fonte": {"type": ["string", "null"], "description": "Riferimento BREVE nel CGA da cui hai tratto i valori: pagina e/o articolo. Es: 'p.35 Art.3.4' o 'Art. 2.4.4'. null se non identificabile."},
                            "confidenza": {"type": ["string", "null"], "enum": ["alta", "media", "bassa", None], "description": "Quanto sei sicuro dei valori estratti per questa sezione: 'alta' (valore esplicito e inequivocabile nel testo), 'media' (dedotto o da tabella ambigua), 'bassa' (incerto, da verificare). null se non valutabile."},
                        },
                        "required": ["id", "nome", "inclusa", "opzionale", "massimale_num"]
                    }
                },
                "punti_di_forza": {"type": "array", "items": {"type": "string"}, "description": "Max 4 punti concreti con valori numerici"},
                "esclusioni":     {"type": "array", "items": {"type": "string"}, "description": "Max 5 esclusioni sorprendenti per il cliente"},
                "consigliata_per":{"type": ["string", "null"]},
            },
            "required": ["tipo", "sezioni"]
        }
    }


# ── PROMPT PER ESTRAZIONE A SEZIONI ──────────────────────────────────────────

def _build_sezioni_prompt(filename: str, tipo_hint: str = "") -> str:
    tipo_note = f"\nNOTA: questa polizza è di tipo '{tipo_hint}'. Estrai SOLO le sezioni del tipo corrispondente.\n" if tipo_hint else ""

    garanzie_casa_note = ""
    if tipo_hint in ("Casa", "Multirischio"):
        garanzie_casa_note = """
— GARANZIE_DETAIL (obbligatorio per polizze Casa/Multirischio): compila il campo garanzie_detail con i dettagli di sublimite/scoperto/franchigia per ogni sotto-garanzia.
  Cerca in: tabella riassuntiva, intestazioni di paragrafo, elenchi condizioni, note a fondo sezione.

  ⚠ REGOLE FONDAMENTALI (errori da evitare assolutamente):
  1) LIMITE ≠ SOTTO-CAP SU VOCI SPECIFICHE. Il "sub" è il limite che si applica alla garanzia NEL SUO COMPLESSO. Se la garanzia è coperta fino alla Somma Assicurata e c'è solo un tetto su VOCI PARTICOLARI (es. "eventi atmosferici fino a S.A., ma lastre/coperture/cappotto termico max €20.000"), allora sub=null (è coperta a S.A.); NON mettere il tetto delle voci particolari come limite della garanzia. Quel tetto di nicchia va ignorato o, se rilevante, citato altrove — MAI come limite principale.
  2) NON usare valori di sotto-voci di nicchia come limite della garanzia. Se il limite vero della garanzia non è un importo unico, sub=null (S.A.).
     ESEMPI CONCRETI da NON sbagliare:
     • FENOMENO ELETTRICO: un cap tipo "Stazioni di ricarica/colonnine max €1.000" è il limite di UNA sotto-voce, NON del fenomeno elettrico. Se il fenomeno elettrico è coperto fino alla S.A. → sub=null. MAI mettere €1.000 come limite del fenomeno elettrico. (Se è opzionale: {"opt": true}, non {"opt": true, "sub": "€ 1.000"}.)
     • DANNI D'ACQUA / SPARGIMENTO: un valore tipo "max €15.000 per evento (occlusione/gelo/apparecchiature)" è il cap su EVENTI PARTICOLARI, non il limite generale della garanzia danni d'acqua. Il limite generale è la S.A. → sub=null. MAI mettere €15.000 come limite principale dei danni d'acqua.
     Regola generale: se vedi "max €X relativamente a / per [voci specifiche]" o "limitatamente a [elenco]", quel €X è un sotto-cap → NON è il limite della garanzia.
     ⚠ MA NON ESAGERARE NEL SENSO OPPOSTO: gli esempi sopra valgono SOLO quando l'importo è davvero un cap su voci particolari. Se invece la garanzia ha un LIMITE COMPLESSIVO REALE (es. "Danni d'acqua: massimo €5.000 per sinistro" senza riferimento a voci specifiche), allora quello È il limite e va riportato in sub. Non forzare "S.A." dove esiste un limite vero della garanzia. Distingui caso per caso leggendo il testo, non applicare gli esempi alla cieca.
  3) GARANZIA OPERANTE SOLO SE ACQUISTATA UN'ALTRA GARANZIA: se il testo dice che una garanzia è coperta "salvo/solo quanto previsto dalla garanzia supplementare X, se acquistata" oppure "se acquistata la garanzia", allora NON è inclusa nella base ma è OPZIONALE → imposta il campo "opt": true sulla sotto-garanzia (es. eventi_atm: {"opt": true} oppure {"opt": true, "sub": "..."} se il supplemento ha un limite). NON lasciarla come inclusa (≠ {} che significa inclusa a S.A.). NON inventare un limite.
     ⚠ "opt" SOLO con frase esplicita di acquisto separato ("supplementare", "a pagamento", "acquistabile a parte", "se acquistata", "facoltativa a premio"). Se invece la garanzia/evento è ELENCATA tra i rischi coperti dalla garanzia BASE (anche se vicino a un elenco di opzionali — es. "atti vandalici" tra gli eventi base dell'Incendio), allora è INCLUSA, NON opt. Nel dubbio, senza una frase esplicita di acquisto separato → inclusa ({}), non opt.
  sub = sublimite monetario specifico (es: "€ 3.000", "10% del massimale"). Se la garanzia è coperta dal massimale generale senza sublimite → null (verrà mostrata come "S.A.").
  scop = scoperto percentuale a carico dell'assicurato (es: "20% min. €250"). null se assente.
  fra = franchigia fissa a carico dell'assicurato (es: "€ 500"). null se assente.
  Per le garanzie RC (rc_figli, rc_cani, rc_inquin, rc_incend): se coperte dal massimale RC generale senza limiti specifici → {"sub": null, "scop": null, "fra": null}. null solo se escluse.
  ASSISTENZA — regola critica: per ass_idraul/ass_elett/ass_fabbro il "sub" è il limite per SINGOLO invio artigiano. Cerca nell'articolo dedicato PER TIPO (es: "Art. X Invio idraulico", "Art. X Invio elettricista", "Art. X Invio fabbro"). NON prendere valori da tabelle riassuntive generali. Se non trovi il valore esplicito → {{"sub": null, "scop": null, "fra": null}}. MAI inventare valori.
  ASSISTENZA — pattern Unipol: se trovi "massimo complessivo €X per evento, con un massimo di €Y per artigiano" → ass_idraul.sub=ass_elett.sub=ass_fabbro.sub="€ Y".
  ASSISTENZA — alloggio ≠ artigiani: ass_allogg.sub (pernottamento/hotel) ha quasi sempre un limite DIVERSO e MAGGIORE rispetto agli artigiani (tipicamente €300 vs €250). NON usare il valore alloggio per idraulico/elettricista/fabbro.
  RC — rc_inquin: se il testo RC esclude esplicitamente l'inquinamento (es: "non comprende i danni da inquinamento o contaminazione") → rc_inquin=null. Altrimenti → {{"sub": null, "scop": null, "fra": null}}.
  INCENDIO — demolizione: riporta ESATTAMENTE come scritto ("30% dell'indennizzo" ≠ "5% del massimale"). Non confondere.
  INCENDIO — ricerca_guasto: cerca il massimale fisso NELL'ARTICOLO DEDICATO (es: "max €2.500"), non nelle tabelle generali.
  SCHEMA ESTENSIBILE — sotto-garanzie EXTRA: se una sotto-garanzia ha un PROPRIO limite/scoperto/franchigia ma NON rientra negli id standard elencati sopra, AGGIUNGILA comunque dentro "gz" con un id descrittivo in snake_case e un campo "nome" leggibile — non scartarla. Esempi reali: Furto "oggetti nelle dipendenze" (scoperto 10% min €250), "Preziosi e valori in banca" (scoperto 10%). Formato: "furto": {{"gz": {{..., "furto_dipendenze": {{"nome": "Furto oggetti nelle dipendenze", "scop": "10% min. €250"}}, "preziosi_banca": {{"nome": "Preziosi e valori in banca", "scop": "10%"}}}}}}. REGOLA D'ORO: non perdere MAI uno scoperto/franchigia/limite solo perché la sotto-garanzia non è in elenco — creale una riga extra con nome. ⚠ Per lo STESSO concetto usa SEMPRE lo stesso "nome" leggibile tra compagnie diverse (es. sempre "Furto oggetti nelle dipendenze", non a volte "Dipendenze" a volte "Oggetti in dipendenza"): così nel confronto le righe extra si allineano.
  FONTE E CONFIDENZA (per ogni sotto-garanzia, facoltativi ma consigliati): aggiungi "fonte" = riferimento BREVE da cui hai tratto i valori (pagina e/o articolo, es. "p.35 Art.3.4.2"); e "conf" = quanto sei sicuro: "alta" (valore esplicito e inequivocabile), "media" (dedotto o da tabella ambigua), "bassa" (incerto, da verificare). Es: "preziosi": {{"sub": "10% SA max €10.000", "fonte": "p.36 Art.3.2", "conf": "alta"}}. Usa "bassa" quando NON sei sicuro invece di inventare: è preferibile un valore segnalato come incerto."""

    sinonimi_casa_txt = "\n".join(
        f"  • '{d['nome_standard']}' (id: {sid}) — sinonimi: {', '.join(d['sinonimi'][:5])}"
        for sid, d in SINONIMI_SEZIONI_CASA.items()
    )
    sinonimi_infortuni_txt = "\n".join(
        f"  • '{d['nome_standard']}' (id: {sid}) — sinonimi: {', '.join(d['sinonimi'][:5])}"
        for sid, d in SINONIMI_SEZIONI_INFORTUNI.items()
    )
    sinonimi_salute_txt = "\n".join(
        f"  • '{d['nome_standard']}' (id: {sid}) — sinonimi: {', '.join(d['sinonimi'][:5])}"
        for sid, d in SINONIMI_SEZIONI_SALUTE.items()
    )
    sinonimi_rcauto_txt = "\n".join(
        f"  • '{d['nome_standard']}' (id: {sid}) — sinonimi: {', '.join(d['sinonimi'][:5])}"
        for sid, d in SINONIMI_SEZIONI_RCAUTO.items()
    )
    sinonimi_aziendale_txt = "\n".join(
        f"  • '{d['nome_standard']}' (id: {sid}) — sinonimi: {', '.join(d['sinonimi'][:5])}"
        for sid, d in SINONIMI_SEZIONI_AZIENDALE.items()
    )

    # Guida specifica ramo Aziendale (multirischio PMI)
    aziendale_note = ""
    if tipo_hint == "Aziendale":
        aziendale_note = """
— POLIZZE AZIENDALI (multirischio PMI) — struttura a sezioni con sotto-limiti in "gz":
  • Danni ai beni: massimale di sezione + "gz" per le partite — {{"fabbricato": {{...}}, "contenuto": {{...}}, "macchinari": {{...}}, "merci": {{...}}, "ricorso_terzi": {{...}}}}.
  • Furto: forma (primo rischio assoluto/relativo) nel testo; "gz" per valori in cassaforte, merci all'aperto, portavalori.
  • RC: estrai i MASSIMALI fissi per RCT, RCO/RCI, RC prodotti come sezioni distinte (rct, rco, rc_prodotti). Nel campo note: massimale per sinistro/per persona, retroattività/postuma.
  • PROTEZIONE DEL REDDITO (interruzione attività): è un indennizzo A TEMPO. Metti il massimale di sezione e nel "gz" le forme: {{"diaria": {{"nome": "Diaria giornaliera", "sub": "€X/gg per max N gg"}}, "perdita_pigioni": {{...}}, "maggiori_costi": {{...}}}}. Nel campo note specifica il periodo di indennizzo.
  • Cyber (protezione digitale): massimale + sotto-limiti (danni propri vs RC, ripristino dati) in "gz".
  Le sezioni aziendali sono spesso attivabili a blocchi: marca inclusa/opzionale secondo il testo."""

    # Guida specifica ramo RC Auto
    rcauto_note = ""
    if tipo_hint == "RC Auto":
        rcauto_note = """
— POLIZZE RC AUTO — massimali e franchigie:
  • RCA: massimale FISSO nel testo (es. "€6.450.000 danni a persone + €1.300.000 cose", o unico "€7.500.000"). Estrai i valori esatti, MAI "Somma assicurata".
  • Kasko / Furto e incendio / Eventi naturali: massimale = "Valore del veicolo" (massimale_num=0). Riporta la franchigia/scoperto ESATTI (es. fra "€500", scop "15% min. €500"). Furto e incendio possono avere franchigie diverse → usa "gz" con voci "furto" e "incendio" se distinte.
  • Cristalli: massimale fisso (es. "€1.500") o "Valore del cristallo"; riporta la franchigia (es. "€100").
  • Infortuni del conducente: capitali FISSI → mettili in "gz": {{"morte": {{"nome": "Morte", "sub": "€100.000"}}, "ip": {{"nome": "Invalidità permanente", "sub": "€200.000"}}}}.
  • Assistenza stradale: sotto-limiti in "gz": {{"traino": {{"nome": "Traino", "sub": "fino a X km"}}, "auto_sostitutiva": {{"nome": "Auto sostitutiva", "sub": "X giorni"}}}}.
  Cerca i valori in "DIP", "DIP Aggiuntivo", "Condizioni di Assicurazione", "Tabella delle garanzie/massimali"."""

    # Guida specifica per ramo Salute (modello per canale)
    salute_note = ""
    if tipo_hint == "Salute":
        salute_note = """
— POLIZZE SALUTE — UNA RIGA PER CANALE: ricovero, alta diagnostica e visite specialistiche hanno
  quasi sempre valori DIVERSI a seconda della struttura usata. Crea una SEZIONE separata per ciascun
  canale presente nel documento, usando gli id dedicati:
    ricovero  → ricovero_conv (convenzionate), ricovero_nonconv (non convenzionate), ricovero_ssn (SSN);
    alta diagnostica → alta_diagnostica_conv / alta_diagnostica_nonconv / alta_diagnostica_ssn;
    visite specialistiche → visite_conv / visite_nonconv / visite_ssn.
  Per ogni riga compila massimale, scoperto e franchigia SPECIFICI di quel canale (es. convenzionato:
  nessuno scoperto; non convenzionato: scoperto 25% min €250; SSN: indennità sostitutiva).
— SALUTE — limiti temporali: per pre/post ricovero riporta la finestra nel campo "note" o "sublimiti"
  (es. "60 gg prima / 100 gg dopo"). Per il ricovero SSN usa massimale = indennità sostitutiva (es. "150 €/giorno").
— SALUTE — valori personalizzati: se massimale/scoperto/franchigia sono rimandati al contratto, scrivi
  "indicato in Polizza" invece di lasciare vuoto (la garanzia esiste, il valore è personalizzato).
— SALUTE — canale assente: se un canale non è previsto dal prodotto, NON creare quella riga (verrà mostrato "—").
"""

    # Mostra solo il dizionario rilevante per il tipo noto, entrambi se sconosciuto
    if tipo_hint == "Casa":
        dizionario_txt = f"POLIZZE CASA:\n{sinonimi_casa_txt}"
    elif tipo_hint == "Infortuni":
        dizionario_txt = f"POLIZZE INFORTUNI:\n{sinonimi_infortuni_txt}"
    elif tipo_hint == "Salute":
        dizionario_txt = f"POLIZZE SALUTE:\n{sinonimi_salute_txt}"
    elif tipo_hint == "RC Auto":
        dizionario_txt = f"POLIZZE RC AUTO:\n{sinonimi_rcauto_txt}"
    elif tipo_hint == "Aziendale":
        dizionario_txt = f"POLIZZE AZIENDALI (multirischio PMI):\n{sinonimi_aziendale_txt}"
    elif tipo_hint == "Multirischio":
        dizionario_txt = f"POLIZZE CASA:\n{sinonimi_casa_txt}\n\nPOLIZZE INFORTUNI:\n{sinonimi_infortuni_txt}"
    else:
        dizionario_txt = f"POLIZZE CASA:\n{sinonimi_casa_txt}\n\nPOLIZZE INFORTUNI:\n{sinonimi_infortuni_txt}\n\nPOLIZZE SALUTE:\n{sinonimi_salute_txt}"

    return f"""Sei un esperto di polizze assicurative italiane. Analizza questo documento (file: {filename}) e usa la funzione extract_sezioni.
{tipo_note}

DIZIONARIO SINONIMI — le compagnie usano nomi diversi per le stesse sezioni. Usa questo mapping per riconoscere le sezioni e normalizzare al nome standard:

{dizionario_txt}

REGOLE CRITICHE:
— id e nome: usa SEMPRE i valori standard dal dizionario sopra. Es: "Morte da infortuni" di Tandem → id="morte", nome="Morte da infortuni"
— POLIZZE INFORTUNI: distingui "assistenza_sanitaria" (id=assistenza_sanitaria, per infortuni/salute — infermiere, fisioterapista, rimpatrio) da "assistenza" (id=assistenza, solo per polizze Casa — idraulico, vetraio, fabbro). Per polizze Infortuni usa SEMPRE id="assistenza_sanitaria".
— POLIZZE MODULARI (es. Tandem): anche se una garanzia richiede attivazione specifica nella scheda, se è descritta nel testo come garanzia della sezione Infortuni mettila come inclusa=false, opzionale=true. NON metterla assente se è chiaramente descritta nel documento.
— TUTELA LEGALE nelle polizze CASA: se nel testo c'è una sezione "Tutela Legale" con le sue condizioni (massimale, articoli, carenza), mettila come inclusa=true anche se il massimale è variabile o "indicato in polizza". La presenza della sezione nel contratto = garanzia inclusa.
— TUTELA LEGALE nelle polizze INFORTUNI: se presente (anche con massimale fisso), estraila come id="tutela_legale". Nel campo note includi: limite per paesi extra-lista se presente (es: "Paesi extra-lista: max €5.000"), distinzione Italia/EU vs extra-EU, massimale per sinistro e annuale.
— MASSIMALE "Indicato in Polizza" o "Variabile": se il testo dice che il massimale è scelto dal contraente o indicato in polizza, usa massimale="Indicato in Polizza" e inclusa=true (non opzionale).
— "Morte da infortuni" / "7.1 Morte da infortuno": se presente nel testo della polizza (anche come sezione 7.1), estraila sempre. Per Tandem è una garanzia della sezione Infortuni → id="morte", inclusa=true (o opzionale=true se modulare).
— massimale: per Incendio/Furto/Infortuni usa "Somma assicurata". Per RC cerca il valore fisso (es: €5.000.000). Se il testo dice "massimale indicato in polizza" usa "Indicato in Polizza" e massimale_num=0.
— ⚠ MASSIMALE ≠ SOTTO-CAP: il massimale di una sezione è il limite complessivo. Se la sezione copre fino alla Somma Assicurata e c'è solo un tetto su voci particolari (es. lastre/coperture/cappotto max €20.000), il massimale resta "Somma assicurata"; il tetto di nicchia NON è il massimale. Non usare valori di sotto-voci di nicchia (es. cap colonnine di ricarica) come massimale della sezione.
— ⚠ GARANZIA OPERANTE SOLO SE ACQUISTATA: se una garanzia/sezione è coperta "solo/salvo se acquistata la garanzia supplementare X" → inclusa=false, opzionale=true (NON è nella base). Non inventare un massimale. MA opzionale=true SOLO con frase esplicita di acquisto separato ("supplementare", "a pagamento", "acquistabile a parte", "se acquistata", "facoltativa a premio"): se la garanzia è elencata tra i rischi della base (anche se vicino a un elenco di opzionali), è inclusa=true. Nel dubbio → inclusa.
— ⚠ SEZIONE NON PRESENTE NEL DOCUMENTO: estrai una sezione SOLO se è descritta nel documento o esplicitamente esclusa. Se una sezione (es. Responsabilità Civile, Tutela Legale) NON compare perché è un modulo separato, NON emetterla affatto e NON marcarla come esclusa: ometterla. Usa inclusa=false+opzionale=false SOLO quando il documento la esclude esplicitamente.
— franchigia e scoperto: estrai SEMPRE con il minimo in € quando presente (es: "10% min. €250"). Per infortuni cerca la tabella riassuntiva.
— FRANCHIGIE PROGRESSIVE: se la franchigia varia per scaglioni (es. in base al % di IP o all'importo), usa il formato: "X% (≤€Nk) / Y% (€Nk-€Mk) / Z% (>€Mk)". Es: "3% (≤€250k) / 10% (€250k-€650k) / 15% (>€650k)". Per IP con soglia fissa: "franchigia 25% sotto soglia / 0% oltre soglia" → "0% (IP ≥ soglia) / 25% (IP < soglia)".
— PIÙ OPZIONI FRANCHIGIA: se esistono più alternative per la stessa garanzia (es. "franchigia 24% o 65%", oppure più livelli di franchigia opzionali), riportale TUTTE separate da " o ": franchigia="24% o 65%". NON scegliere una sola opzione — riporta tutte quelle indicate nel testo.
— sublimiti: formato "Voce max €X | Voce max €Y". Per Furto: gioielli, valori, scippo fuori. Per Assistenza sanitaria: limiti per tipo prestazione: "Infermiere max €X/gg | Fisioterapista max €X/sett | Cure dentarie max €X | Protesi max €X | Riabilitazione max €X | Rimpatrio: incluso/max €X".
— sotto_garanzie: per Casa indica quali sotto-garanzie sono incluse (true/false) o il loro valore (es: "max €15.000" per gioielli).
— SEZIONI INFORTUNI DISTINTE: estraile come sezioni SEPARATE con id diversi quando il documento le distingue:
    • IP base (id=ip_infortuni) vs IP Grave/≥65% (id=ip_infortuni_grave) — separa SOLO se il documento descrive due garanzie distinte
    • Diaria ricovero (id=diaria_ricovero) vs Diaria post-ricovero/convalescenza (id=diaria_post_ricovero)
    • Diaria inabilità da infortuni (id=diaria_inabilita) vs da malattia (id=diaria_inabilita_malattia)
    • Rendita da infortuni (id=rendita_vitalizia) vs da malattia (id=rendita_malattia)
    • Rimborso spese da infortuni (id=rss_infortuni) vs da malattia (id=rss_malattia)
    NON accorpare garanzie "da infortuni" e "da malattia" in una sola sezione se il documento le presenta separatamente.
— STATO COMATOSO IRREVERSIBILE: se presente come garanzia/sezione separata (non solo menzionata nelle CG generali), estraila come id="stato_comatoso". Nel campo note indica se è legata alla garanzia Morte o autonoma, e la condizione di attivazione (es: "coma > 6 mesi", "stato vegetativo permanente").
— Se una sezione è ESCLUSA esplicitamente: inclusa=false, opzionale=false. Se è opzionale acquistabile: inclusa=false, opzionale=true.
— FRANCHIGIA IN GIORNI (diarie Infortuni/Salute): se una diaria è corrisposta "a partire dal X° giorno", "con una franchigia di N giorni", oppure "i primi N giorni non sono indennizzati", riporta quella franchigia nel campo "franchigia" della sezione ESPRESSA IN GIORNI (es. "7 giorni", "3 giorni", "dall'8° giorno"). È una franchigia vera, solo in giorni anziché in euro: NON lasciarla vuota.
— SOTTO-LIMITI STRUTTURATI (Infortuni e Salute): per ogni sezione, oltre a massimale/scoperto/franchigia, spezza i sotto-limiti numerici nel campo "gz" come voci con "nome" leggibile e i loro sub/scop/fra. Esempio Rimborso spese: gz = {{"protesi": {{"nome": "Protesi anatomiche", "sub": "50% mass. max €5.000"}}, "apparecchiature": {{"nome": "Apparecchiature terapeutiche/ortopediche", "sub": "€2.500"}}, "infermieristica": {{"nome": "Assistenza infermieristica", "sub": "€50/gg x 90 gg"}}, "spese_post_ricovero": {{"nome": "Spese post-ricovero", "sub": "30% SA entro 360 gg"}}}}. NON lasciare i sotto-limiti solo nel testo libero: mettili in "gz" così diventano righe confrontabili. Usa lo STESSO "nome" per lo stesso concetto tra compagnie diverse, così le righe si allineano.
— Estrai TUTTE le sezioni presenti o esplicitamente escluse.{garanzie_casa_note}{salute_note}{rcauto_note}{aziendale_note}"""


# ── MODELLO REQUEST ───────────────────────────────────────────────────────────

class ExtractSezioniRequest(BaseModel):
    pdf_base64: str
    filename: str
    tipo_hint: str = ""  # "Casa" | "Infortuni" | "" (auto)


# ── CORE EXTRACTION FUNCTION ──────────────────────────────────────────────────

async def _detect_tipo_pdf(first_chunk_bytes: bytes, filename: str) -> str:
    """
    Passaggio leggero (Haiku) per rilevare il tipo di polizza dal primo chunk PDF.
    Ritorna: "Casa", "Infortuni", "RC Auto", "Vita", "Multirischio", "Salute", "altro".
    """
    # Usa solo le prime pagine: il tipo si capisce dalla copertina/indice e così
    # non si sfora il contesto di Haiku (200k) su documenti lunghi.
    detect_bytes = first_chunk_bytes
    try:
        reader = PdfReader(io.BytesIO(first_chunk_bytes))
        if len(reader.pages) > 6:
            writer = PdfWriter()
            for i in range(6):
                writer.add_page(reader.pages[i])
            buf = io.BytesIO()
            writer.write(buf)
            detect_bytes = buf.getvalue()
    except Exception:
        detect_bytes = first_chunk_bytes  # se non si riesce a tagliare, prova com'è

    chunk_b64 = base64.b64encode(detect_bytes).decode()
    try:
        msg = await call_claude(
            model=MODEL_FAST,
            max_tokens=50,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": chunk_b64}},
                    {"type": "text", "text": (
                        "Che tipo di polizza assicurativa è questo documento? "
                        "Rispondi con UNA SOLA parola tra: Casa, Infortuni, RC Auto, Vita, Multirischio, Salute, Aziendale, altro. "
                        "Usa 'Aziendale' per polizze rivolte a imprese/attività/PMI (multirischio impresa, capannoni, RC d'impresa). "
                        "Solo la parola, nient'altro."
                    )}
                ]
            }]
        )
        tipo_raw = msg.content[0].text.strip().split()[0] if msg.content else ""
        VALIDI = {"Casa", "Infortuni", "RC Auto", "Vita", "Multirischio", "Salute", "Aziendale", "altro"}
        tipo = tipo_raw if tipo_raw in VALIDI else "Casa"
        logger.info(f"[sezioni] tipo rilevato per '{filename}': {tipo}")
        return tipo
    except Exception as e:
        logger.warning(f"[sezioni] _detect_tipo_pdf fallito per '{filename}': {e} — default Casa")
        return "Casa"


async def _extract_sezioni_chunk(chunk_bytes: bytes, page_start: int, page_end: int,
                                  total_pages: int, filename: str, tipo_hint: str) -> dict:
    """Estrae sezioni da un chunk PDF usando Claude native PDF + tool use."""
    chunk_b64 = base64.b64encode(chunk_bytes).decode()
    chunk_info = f"pagine {page_start + 1}-{page_end} di {total_pages}"
    prompt = _build_sezioni_prompt(filename, tipo_hint) + f"\n\n(stai analizzando {chunk_info})"

    try:
        msg = await call_claude(
            model=MODEL_VISION,
            max_tokens=8192,
            tools=[_sezione_schema(tipo_hint or "Casa")],
            tool_choice={"type": "tool", "name": "extract_sezioni"},
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {"type": "base64", "media_type": "application/pdf", "data": chunk_b64},
                        "cache_control": {"type": "ephemeral"},
                    },
                    {"type": "text", "text": prompt}
                ]
            }]
        )
        if msg.stop_reason == "max_tokens":
            logger.warning(f"[sezioni] TRONCATO (max_tokens) chunk {chunk_info} di '{filename}' — alcune sezioni potrebbero mancare")
        for block in msg.content:
            if block.type == "tool_use":
                return block.input
        return {}
    except Exception as e:
        # Errori di SERVIZIO (credito esaurito, chiave, rate limit): falli emergere
        # così l'endpoint mostra un messaggio chiaro invece di "nessun dato".
        if _ai_error_message(e):
            raise
        logger.error(f"[sezioni] errore chunk {chunk_info} di '{filename}': {e}")
        return {}


def _merge_sezioni(results: list[dict]) -> dict:
    """
    Unisce risultati da chunk multipli dello stesso documento.
    Strategia: sezioni deduplicate per id, preferisce quella con più dati.
    """
    if not results:
        return {}
    if len(results) == 1:
        return results[0]

    merged = results[0].copy()

    # Rileva il tipo dalla maggioranza
    tipi = [r.get("tipo", "") for r in results if r.get("tipo")]
    if tipi:
        merged["tipo"] = max(set(tipi), key=tipi.count)

    # Merge sezioni per id
    sezioni_map: dict[str, dict] = {}
    for r in results:
        for s in r.get("sezioni", []):
            sid = s.get("id", "").strip()
            if not sid:
                continue
            if sid not in sezioni_map:
                sezioni_map[sid] = s
            else:
                existing = sezioni_map[sid]
                # Preferisce record più completo
                def _score(x): return sum(1 for v in x.values() if v is not None and v != 0 and v != "")
                if _score(s) > _score(existing):
                    # Mantieni i campi non-null del vecchio se il nuovo li ha null
                    for k, v in existing.items():
                        if v not in (None, 0, "", False) and s.get(k) in (None, 0, "", False):
                            s[k] = v
                    sezioni_map[sid] = s
                else:
                    # Integra campi mancanti dal nuovo
                    for k in ["franchigia", "scoperto", "sublimiti", "note", "sotto_garanzie"]:
                        if s.get(k) and not existing.get(k):
                            existing[k] = s[k]

    merged["sezioni"] = list(sezioni_map.values())

    # garanzie_detail: DEEP MERGE fra tutti i chunk. Un PDF multi-pagina è diviso in
    # più blocchi e ogni sezione (es. Cristalli, Assistenza) può trovarsi in un blocco
    # diverso: vanno unite TUTTE, non si tiene solo il blocco "migliore" (altrimenti le
    # sezioni dell'altro blocco sparirebbero come "non in doc.").
    gd_merged: dict = {}
    for r in results:
        gd = r.get("garanzie_detail")
        if not isinstance(gd, dict):
            continue
        for sez, data in gd.items():
            if data is None:
                gd_merged.setdefault(sez, None)  # esclusa: tieni solo se non già presente con dati
                continue
            if not isinstance(data, dict):
                continue
            tgt = gd_merged.get(sez)
            if not isinstance(tgt, dict):
                tgt = gd_merged[sez] = {"mass": None, "gz": {}}
            if data.get("mass") and not tgt.get("mass"):
                tgt["mass"] = data["mass"]
            for gzid, gzval in (data.get("gz") or {}).items():
                if gzid not in tgt["gz"]:
                    tgt["gz"][gzid] = gzval
                else:
                    cur = tgt["gz"][gzid]
                    if cur is None and gzval is not None:
                        tgt["gz"][gzid] = gzval
                    elif isinstance(cur, dict) and isinstance(gzval, dict):
                        for k, v in gzval.items():
                            if v and not cur.get(k):
                                cur[k] = v
    if gd_merged:
        merged["garanzie_detail"] = gd_merged

    # Metadati testuali dal primo non-null
    for field in ["compagnia", "prodotto", "premio", "consigliata_per"]:
        for r in results:
            val = r.get(field)
            if val and val != "null":
                merged[field] = val
                break

    # Punti di forza ed esclusioni: unione senza duplicati
    seen: set = set()
    pf = []
    for r in results:
        for p in r.get("punti_di_forza", []):
            if p and p not in seen:
                seen.add(p); pf.append(p)
    merged["punti_di_forza"] = pf[:4]

    seen = set()
    excl = []
    for r in results:
        for e in r.get("esclusioni", []):
            if e and e not in seen:
                seen.add(e); excl.append(e)
    merged["esclusioni"] = excl[:5]

    return merged


def _normalize_sezioni(result: dict) -> dict:
    """
    Post-processing: normalizza gli id/nomi delle sezioni usando il dizionario sinonimi.
    Gestisce Casa, Infortuni e Multirischio (entrambi i dizionari).
    """
    tipo = result.get("tipo", "Casa")

    # Per Multirischio o tipo sconosciuto, usa entrambi i dizionari
    if tipo == "Infortuni":
        indexes = [(_SYN_INFORTUNI, SINONIMI_SEZIONI_INFORTUNI)]
    elif tipo == "Salute":
        indexes = [(_SYN_SALUTE, SINONIMI_SEZIONI_SALUTE)]
    elif tipo == "RC Auto":
        indexes = [(_SYN_RCAUTO, SINONIMI_SEZIONI_RCAUTO)]
    elif tipo == "Aziendale":
        indexes = [(_SYN_AZIENDALE, SINONIMI_SEZIONI_AZIENDALE)]
    elif tipo in ("Casa", "Vita", "Risparmio"):
        indexes = [(_SYN_CASA, SINONIMI_SEZIONI_CASA)]
    else:  # Multirischio, altro — prova entrambi
        indexes = [(_SYN_CASA, SINONIMI_SEZIONI_CASA), (_SYN_INFORTUNI, SINONIMI_SEZIONI_INFORTUNI)]

    for s in result.get("sezioni", []):
        nome = (s.get("nome") or "").lower().strip()
        matched = False
        for syn_index, sezioni_map in indexes:
            matched_id = syn_index.get(nome)
            if matched_id and matched_id in sezioni_map:
                s["id"] = matched_id
                s["nome"] = sezioni_map[matched_id]["nome_standard"]
                matched = True
                break
        if not matched and not s.get("id"):
            s["id"] = re.sub(r'[^a-z0-9]+', '_', nome)[:30].strip('_')

    return result


async def _refine_sezioni(result: dict, first_chunk_bytes: bytes, filename: str, tipo_hint: str = "Casa") -> dict:
    """
    Secondo passaggio con Opus: recupera franchigie, scoperto e sublimiti mancanti
    nelle sezioni già estratte, usando il PDF originale (primo chunk + più denso).
    Usa lo stesso schema tool e cache_control dell'estrazione iniziale → prompt cache hit sul PDF.
    """
    sezioni = result.get("sezioni", [])
    tipo = result.get("tipo", "Casa")

    # Individua sezioni con dati mancanti rilevanti
    da_completare = []
    for s in sezioni:
        mancanti = []
        if not s.get("franchigia") and s.get("id") in (
            "ip_infortuni", "ip_infortuni_grave", "ip_malattia",
            "rss_infortuni", "rss_malattia",
            "diaria_ricovero", "diaria_post_ricovero",
            "diaria_inabilita", "diaria_inabilita_malattia",
            "rendita_vitalizia", "rendita_malattia",
            "furto", "terremoto_alluvione",
        ):
            mancanti.append("franchigia")
        if not s.get("scoperto") and s.get("id") in (
            "rss_infortuni", "rss_malattia",
            "furto", "terremoto_alluvione",
        ):
            mancanti.append("scoperto")
        if not s.get("sublimiti") and s.get("id") in (
            "furto", "assistenza", "assistenza_sanitaria", "tutela_legale",
            "rc", "terremoto_alluvione",
        ):
            mancanti.append("sublimiti")
        if mancanti:
            da_completare.append({"id": s["id"], "nome": s.get("nome", ""), "mancanti": mancanti})

    if not da_completare:
        return result  # Nulla da completare

    sezioni_json = json.dumps(sezioni, ensure_ascii=False, indent=2)
    da_completare_json = json.dumps(da_completare, ensure_ascii=False, indent=2)
    chunk_b64 = base64.b64encode(first_chunk_bytes).decode()

    prompt = f"""Hai estratto le sezioni di questa polizza assicurativa italiana (file: {filename}, tipo: {tipo}).
Alcune sezioni hanno valori mancanti. Cerca ESCLUSIVAMENTE nel documento i valori mancanti e aggiorna le sezioni.

SEZIONI GIÀ ESTRATTE:
{sezioni_json}

VALORI DA TROVARE (cerca SOLO questi):
{da_completare_json}

ISTRUZIONI DI RICERCA:
— franchigia: cerca nelle tabelle "Franchigie", "TABELLA RIASSUNTIVA", "Limitazioni". Per infortuni: può essere in giorni (es: "5 giorni") o in % (es: "franchigia 5%"). Per IP progressive: "3% (≤€250k) / 10% (€250k-€650k)".
— scoperto: cerca "Scoperto X% con il minimo di €YYY" → scrivi "X% min. €YYY". Per rimborso spese infortuni: tipicamente "20% min. €75".
— sublimiti: cerca limiti per sotto-voci. Per furto: gioielli, valori, scippo. Per assistenza: €/evento per tipo intervento. Per tutela legale: massimale per sinistro/anno, paesi extra-lista.

REGOLE:
— Aggiorna SOLO i campi "mancanti" elencati sopra — non toccare i valori già presenti
— Se non trovi il valore nel documento, lascia il campo invariato (null)
— NON inventare valori

Restituisci SOLO un JSON con questa struttura:
{{"sezioni": [ ...array completo aggiornato... ]}}"""

    try:
        # Stessi tools e cache_control usati in _extract_sezioni_chunk → prompt cache hit sul PDF
        msg = await call_claude(
            model=MODEL_VISION,
            max_tokens=4096,
            tools=[_sezione_schema(tipo_hint)],
            tool_choice={"type": "tool", "name": "extract_sezioni"},
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {"type": "base64", "media_type": "application/pdf", "data": chunk_b64},
                        "cache_control": {"type": "ephemeral"},
                    },
                    {"type": "text", "text": prompt}
                ]
            }]
        )
        # Parsing tool_use (stesso formato di _extract_sezioni_chunk)
        updated_sezioni = None
        for block in msg.content:
            if block.type == "tool_use":
                updated_sezioni = block.input.get("sezioni", [])
                break
        if updated_sezioni:
            updated_map = {s.get("id"): s for s in updated_sezioni}
            for s in result["sezioni"]:
                sid = s.get("id")
                if sid in updated_map:
                    for campo in ["franchigia", "scoperto", "sublimiti", "note"]:
                        nuovo_val = updated_map[sid].get(campo)
                        if nuovo_val and not s.get(campo):
                            s[campo] = nuovo_val
            logger.info(f"[sezioni] raffinamento completato per '{filename}' "
                        f"(cache_read={getattr(msg.usage, 'cache_read_input_tokens', 0)} tok)")
    except Exception as e:
        logger.warning(f"[sezioni] raffinamento fallito per '{filename}': {e} — usando dati originali")

    return result


# ── ENDPOINT: POST /api/extract-sezioni ──────────────────────────────────────

@app.post("/api/extract-sezioni")
async def extract_sezioni(req: ExtractSezioniRequest):
    """
    Estrazione a sezioni — versione sincrona.
    Input: PDF in base64 + filename + tipo_hint opzionale.
    Output: JSON con sezioni (incendio, furto, RC, ecc.) invece di lista piatta.
    """
    try:
        pdf_bytes = base64.b64decode(req.pdf_base64)
    except Exception:
        raise HTTPException(400, "pdf_base64 non valido")

    if len(pdf_bytes) < 100:
        raise HTTPException(400, "PDF troppo piccolo o vuoto")
    _check_pdf_limits(pdf_bytes)

    # Cache
    cache_key = _cache_key(req.pdf_base64[:2000] + str(len(pdf_bytes)) + "v3sezioni")
    if cache_key in _extraction_cache:
        logger.info(f"[sezioni] '{req.filename}' — cache hit")
        return _extraction_cache[cache_key]

    try:
        chunks = _split_pdf_bytes(pdf_bytes, pages_per_chunk=60)
        total = len(chunks)
        logger.info(f"[sezioni] '{req.filename}' → {total} chunk(s), {len(pdf_bytes)//1024}KB")

        # Rileva tipo se non specificato
        tipo_effettivo = req.tipo_hint
        if not tipo_effettivo and chunks:
            tipo_effettivo = await _detect_tipo_pdf(chunks[0][0], req.filename)

        results = await asyncio.gather(*[
            _extract_sezioni_chunk(cb, ps, pe, pt, req.filename, tipo_effettivo)
            for cb, ps, pe, pt in chunks
        ])
        results = [r for r in results if r]
        if not results:
            raise HTTPException(500, "Nessun dato estratto dal PDF")

        result = _merge_sezioni(results) if len(results) > 1 else results[0]
        result = _normalize_sezioni(result)
        result = await _refine_sezioni(result, chunks[0][0], req.filename, tipo_effettivo)
        _extraction_cache[cache_key] = result
        return result

    except HTTPException:
        raise
    except Exception as e:
        friendly = _ai_error_message(e)
        if friendly:
            raise HTTPException(503, friendly)
        logger.error(f"[sezioni] errore '{req.filename}': {e}")
        raise HTTPException(500, "Errore durante l'analisi per sezioni")


# ── ENDPOINT: POST /api/extract-sezioni-stream ───────────────────────────────

@app.post("/api/extract-sezioni-stream")
async def extract_sezioni_stream(req: ExtractSezioniRequest):
    """
    Versione streaming SSE di /api/extract-sezioni.
    Invia eventi progress/result come gli altri endpoint stream.
    """
    try:
        pdf_bytes = base64.b64decode(req.pdf_base64)
    except Exception:
        raise HTTPException(400, "pdf_base64 non valido")

    if len(pdf_bytes) < 100:
        raise HTTPException(400, "PDF troppo piccolo o vuoto")
    _check_pdf_limits(pdf_bytes)

    async def generate():
        queue: asyncio.Queue = asyncio.Queue()

        async def do_extract():
            try:
                cache_key = _cache_key(req.pdf_base64[:2000] + str(len(pdf_bytes)) + "v3sezioni")
                if cache_key in _extraction_cache:
                    await queue.put({"type": "progress", "step": "Risultato dalla cache...", "pct": 95})
                    await queue.put({"type": "result", "data": _extraction_cache[cache_key]})
                    return

                chunks = _split_pdf_bytes(pdf_bytes, pages_per_chunk=60)
                total = len(chunks)
                await queue.put({"type": "progress", "step": f"Lettura PDF ({total} sezioni, {len(pdf_bytes)//1024}KB)...", "pct": 5})

                # Rileva tipo se non specificato
                tipo_effettivo = req.tipo_hint
                if not tipo_effettivo and chunks:
                    await queue.put({"type": "progress", "step": "Rilevamento tipo polizza...", "pct": 10})
                    tipo_effettivo = await _detect_tipo_pdf(chunks[0][0], req.filename)
                    await queue.put({"type": "progress", "step": f"Tipo rilevato: {tipo_effettivo}. Estrazione in corso...", "pct": 15})

                results = await asyncio.gather(*[
                    _extract_sezioni_chunk(cb, ps, pe, pt, req.filename, tipo_effettivo)
                    for cb, ps, pe, pt in chunks
                ])
                await queue.put({"type": "progress", "step": "Normalizzazione sezioni...", "pct": 80})

                results = [r for r in results if r]
                if not results:
                    await queue.put({"type": "error", "message": "Nessun dato estratto dal PDF"})
                    return

                result = _merge_sezioni(results) if len(results) > 1 else results[0]
                await queue.put({"type": "progress", "step": "Applicazione dizionario sinonimi...", "pct": 88})
                result = _normalize_sezioni(result)
                await queue.put({"type": "progress", "step": "Raffinamento valori mancanti...", "pct": 93})
                result = await _refine_sezioni(result, chunks[0][0], req.filename, tipo_effettivo)
                _extraction_cache[cache_key] = result
                await queue.put({"type": "result", "data": result})

            except Exception as e:
                friendly = _ai_error_message(e)
                if not friendly:
                    logger.error(f"[sezioni stream] errore '{req.filename}': {e}")
                await queue.put({"type": "error", "message": friendly or "Errore durante l'analisi"})

        task = asyncio.create_task(do_extract())
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=3.0)
                    yield f"data: {json.dumps(msg, ensure_ascii=False)}\n\n"
                    if msg["type"] in ("result", "error"):
                        break
                except asyncio.TimeoutError:
                    yield 'data: {"type":"ping"}\n\n'
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                                      "Connection": "keep-alive"})

# ── FINE ESTRAZIONE PER SEZIONI (v3) ─────────────────────────────────────────


# ══════════════════════════════════════════════════════════════════════════════
# ── LIBRERIA CGA — SYNC AUTOMATICO ────────────────────────────────────────────
# Scarica le CGA pubbliche delle compagnie, controlla aggiornamenti via hash,
# ri-estrae con pipeline v3 se cambiata, salva in Qdrant collection separata.
# Endpoints:
#   GET  /api/library          — lista polizze in libreria
#   POST /api/library/sync     — sincronizza tutto il catalogo (o una singola entry)
#   GET  /api/library/catalog  — restituisce il catalogo con stato corrente
# ══════════════════════════════════════════════════════════════════════════════

import pathlib

# ── STORAGE PERSISTENTE ───────────────────────────────────────────────────────
# Se Railway Volume è montato su /data lo usiamo (persiste tra deploy).
# Fallback: /app/data (ephemeral, ma funziona tra restart).
_DATA_DIR = pathlib.Path("/data") if pathlib.Path("/data").exists() else pathlib.Path(__file__).parent / "data"
_DATA_DIR.mkdir(parents=True, exist_ok=True)

PDF_CACHE_DIR = _DATA_DIR / "pdf_cache"
PDF_CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Catalogo: priorità a /data/cga_catalog.json (persistente), fallback a quello in repo
_CATALOG_PATH_PERSISTENT = _DATA_DIR / "cga_catalog.json"
_CATALOG_PATH_REPO       = pathlib.Path(__file__).parent / "cga_catalog.json"

_LIBRARY_COLLECTION = "cga_library"
_LIBRARY_PID_PREFIX = "lib:"  # es: "lib:unipol-unica-casa"

# Header browser realistici per bypassare blocchi anti-bot dei siti assicurativi
_BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/pdf,*/*;q=0.8",
    "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}


def _load_catalog() -> list[dict]:
    """
    Legge il catalogo da storage persistente.
    Al primo avvio (file persistente assente) copia dal repo e fa merge:
    le entry del repo vengono aggiunte se non presenti, senza sovrascrivere
    quelle già estratte nel persistente.
    """
    repo_catalog: list[dict] = []
    if _CATALOG_PATH_REPO.exists():
        with open(_CATALOG_PATH_REPO, "r", encoding="utf-8") as f:
            repo_catalog = json.load(f)

    if not _CATALOG_PATH_PERSISTENT.exists():
        # Prima volta: copia il catalogo del repo nel persistente
        _save_catalog(repo_catalog)
        return repo_catalog

    with open(_CATALOG_PATH_PERSISTENT, "r", encoding="utf-8") as f:
        persistent = json.load(f)

    # Merge: aggiungi nuove entry + aggiorna url/url_type/prodotto/compagnia dal repo
    persistent_map = {e["id"]: e for e in persistent}
    added = 0
    updated = 0
    for entry in repo_catalog:
        if entry["id"] not in persistent_map:
            persistent.append(entry)
            persistent_map[entry["id"]] = entry
            added += 1
        else:
            # Aggiorna metadati statici dal repo (URL, nomi) senza toccare dati estratti
            existing = persistent_map[entry["id"]]
            changed = False
            for field in ("url", "url_type", "prodotto", "compagnia", "tipo", "note"):
                if entry.get(field) != existing.get(field):
                    existing[field] = entry.get(field)
                    changed = True
            if changed:
                updated += 1
    if added or updated:
        logger.info(f"[catalog] Merge: {added} nuove entry, {updated} URL aggiornati dal repo")
        _save_catalog(persistent)

    return persistent


_catalog_write_lock = threading.Lock()

def _save_catalog(catalog: list[dict]):
    """Salva il catalogo nel path persistente (thread-safe)."""
    with _catalog_write_lock:
        with open(_CATALOG_PATH_PERSISTENT, "w", encoding="utf-8") as f:
            json.dump(catalog, f, ensure_ascii=False, indent=2)


async def _q_get_library(entry_id: str) -> dict | None:
    """Legge una entry della libreria da Qdrant."""
    pid = _LIBRARY_PID_PREFIX + entry_id
    if not QDRANT_URL or not _qdrant_ok:
        return None
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            r = await http.get(
                f"{QDRANT_URL}/collections/{_LIBRARY_COLLECTION}/points/{pid}",
                headers=_qh()
            )
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json().get("result", {}).get("payload", {}).get("data")
    except Exception as e:
        logger.error(f"[library] get {entry_id}: {e}")
        return None


async def _q_set_library(entry_id: str, data: dict):
    """Salva una entry della libreria in Qdrant."""
    pid = _LIBRARY_PID_PREFIX + entry_id
    if not QDRANT_URL or not _qdrant_ok:
        return
    try:
        async with httpx.AsyncClient(timeout=15.0) as http:
            r = await http.put(
                f"{QDRANT_URL}/collections/{_LIBRARY_COLLECTION}/points",
                headers=_qh(),
                json={"points": [{"id": pid, "vector": [0.0], "payload": {"data": data}}]}
            )
            r.raise_for_status()
    except Exception as e:
        logger.error(f"[library] set {entry_id}: {e}")


async def _ensure_library_collection():
    """Crea la collection libreria se non esiste."""
    if not QDRANT_URL or not _qdrant_ok:
        return
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            r = await http.get(f"{QDRANT_URL}/collections/{_LIBRARY_COLLECTION}", headers=_qh())
            if r.status_code == 404:
                r2 = await http.put(
                    f"{QDRANT_URL}/collections/{_LIBRARY_COLLECTION}",
                    headers=_qh(),
                    json={"vectors": {"size": 1, "distance": "Cosine"}}
                )
                if r2.status_code in (200, 201):
                    logger.info(f"[library] Collection '{_LIBRARY_COLLECTION}' creata")
    except Exception as e:
        logger.error(f"[library] ensure collection: {e}")


async def _sync_entry(entry: dict) -> dict:
    """
    Sincronizza una singola entry del catalogo:
    1. Scarica il PDF dall'URL
    2. Calcola hash MD5
    3. Se hash diverso dall'ultimo → ri-estrae con v3
    4. Aggiorna Qdrant e il catalogo
    Restituisce entry aggiornata con status.
    """
    entry_id = entry["id"]
    url = entry.get("url", "")
    logger.info(f"[library sync] '{entry_id}' — {url}")

    # Percorso cache locale per questo entry
    _pdf_cache_file = PDF_CACHE_DIR / f"{entry_id}.pdf"

    try:
        pdf_bytes: bytes | None = None

        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as http:
            # Primo tentativo con header browser completi
            r = await http.get(url, headers=_BROWSER_HEADERS)

            # Alcuni siti vogliono prima una visita alla homepage (cookie/session)
            if r.status_code in (400, 403, 429):
                from urllib.parse import urlparse
                origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                logger.info(f"[library sync] '{entry_id}' — HTTP {r.status_code}, provo con Referer {origin}")
                headers_with_ref = {**_BROWSER_HEADERS, "Referer": origin}
                r = await http.get(url, headers=headers_with_ref)

            if r.status_code == 200:
                content_type = r.headers.get("content-type", "")
                if "html" in content_type and not url.lower().endswith(".pdf"):
                    logger.warning(f"[library sync] '{entry_id}' — risposta HTML invece di PDF")
                else:
                    pdf_bytes = r.content

            if pdf_bytes is None:
                # URL fallito — prova la cache locale
                if _pdf_cache_file.exists():
                    logger.info(f"[library sync] '{entry_id}' — URL fallito (HTTP {r.status_code}), uso cache locale")
                    pdf_bytes = _pdf_cache_file.read_bytes()
                else:
                    logger.warning(f"[library sync] '{entry_id}' — HTTP {r.status_code}, nessuna cache disponibile")
                    return {**entry, "sync_status": "error", "sync_error": f"HTTP {r.status_code}"}

        if len(pdf_bytes) < 500:
            return {**entry, "sync_status": "error", "sync_error": "PDF troppo piccolo"}

        # Salva sempre una copia locale (aggiorna se cambiato)
        try:
            _pdf_cache_file.write_bytes(pdf_bytes)
            logger.info(f"[library sync] '{entry_id}' — PDF salvato in cache locale ({len(pdf_bytes)//1024}KB)")
        except Exception as ce:
            logger.warning(f"[library sync] '{entry_id}' — impossibile salvare cache: {ce}")

        # Hash del PDF
        new_hash = hashlib.md5(pdf_bytes).hexdigest()
        old_hash = entry.get("last_hash")

        if new_hash == old_hash and entry.get("extracted"):
            logger.info(f"[library sync] '{entry_id}' — nessun cambiamento (hash identico)")
            return {**entry, "sync_status": "unchanged"}

        # Hash diverso (o mai estratto) → estrae
        logger.info(f"[library sync] '{entry_id}' — nuovo hash {new_hash[:8]}... estrazione v3")
        pdf_b64 = base64.b64encode(pdf_bytes).decode()

        chunks = _split_pdf_bytes(pdf_bytes, pages_per_chunk=60)
        results = await asyncio.gather(*[
            _extract_sezioni_chunk(cb, ps, pe, pt, entry.get("prodotto", entry_id), entry.get("tipo", ""))
            for cb, ps, pe, pt in chunks
        ])
        results = [r for r in results if r]

        if not results:
            return {**entry, "sync_status": "error", "sync_error": "Estrazione vuota"}

        extracted = _merge_sezioni(results) if len(results) > 1 else results[0]
        extracted = _normalize_sezioni(extracted)
        extracted["_catalog_id"] = entry_id
        extracted["_url"] = url

        # Salva in Qdrant (best-effort — errori non bloccanti)
        await _q_set_library(entry_id, extracted)

        # Aggiorna entry con nuovo hash, timestamp e dati estratti
        now = __import__("datetime").datetime.utcnow().isoformat() + "Z"
        updated_entry = {
            **entry,
            "last_hash": new_hash,
            "last_updated": now,
            "sync_status": "updated",
            "sync_error": None,
            "extracted": extracted,   # ← incluso nella risposta e salvato nel JSON
        }
        logger.info(f"[library sync] '{entry_id}' — completato ✓")
        return updated_entry

    except Exception as e:
        logger.error(f"[library sync] '{entry_id}' — errore: {e}")
        return {**entry, "sync_status": "error", "sync_error": str(e)[:200]}


# ── ENDPOINTS LIBRERIA ────────────────────────────────────────────────────────

@app.get("/api/library/check-urls")
async def library_check_urls(request: Request, api_key: str = ""):
    """
    Testa tutti gli URL del catalogo CGA e riporta quali funzionano.
    Utile per capire quali polizze sono scaricabili automaticamente.
    """
    # Accetta api_key sia come query param che come header
    key = api_key or request.headers.get("X-API-Key","")
    expected = os.getenv("API_KEY","")
    if expected and key != expected:
        raise HTTPException(status_code=401, detail="API key non valida")
    catalog = _load_catalog()

    async def _check(entry: dict) -> dict:
        url = entry.get("url", "")
        cached = (PDF_CACHE_DIR / f"{entry['id']}.pdf").exists()
        if not url:
            return {"id": entry["id"], "prodotto": entry.get("prodotto","?"),
                    "status": "no_url", "cached": cached}
        try:
            from urllib.parse import urlparse
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as http:
                r = await http.head(url, headers=_BROWSER_HEADERS)
                # Alcuni server non supportano HEAD
                if r.status_code in (405, 501):
                    r = await http.get(url, headers=_BROWSER_HEADERS)
                # Alcuni CDN (es. Allianz) richiedono Referer — ritenta
                if r.status_code in (400, 403):
                    origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                    r = await http.head(url, headers={**_BROWSER_HEADERS, "Referer": origin})
                    if r.status_code in (405, 501):
                        r = await http.get(url, headers={**_BROWSER_HEADERS, "Referer": origin})
            return {"id": entry["id"], "prodotto": entry.get("prodotto","?"),
                    "compagnia": entry.get("compagnia","?"),
                    "status": r.status_code, "cached": cached,
                    "ok": r.status_code == 200}
        except Exception as e:
            return {"id": entry["id"], "prodotto": entry.get("prodotto","?"),
                    "compagnia": entry.get("compagnia","?"),
                    "status": "error", "error": str(e)[:100], "cached": cached, "ok": False}

    results = await asyncio.gather(*[_check(e) for e in catalog])
    ok    = [r for r in results if r.get("ok")]
    fail  = [r for r in results if not r.get("ok")]
    return {"total": len(results), "ok": len(ok), "fail": len(fail), "results": results}


@app.get("/api/library")
async def library_list():
    """Restituisce tutte le polizze estratte in libreria."""
    await _ensure_library_collection()
    catalog = _load_catalog()
    result = []
    for entry in catalog:
        data = await _q_get_library(entry["id"])
        result.append({
            "id": entry["id"],
            "compagnia": entry.get("compagnia"),
            "prodotto": entry.get("prodotto"),
            "tipo": entry.get("tipo"),
            "last_updated": entry.get("last_updated"),
            "sync_status": entry.get("sync_status", "pending"),
            "extracted": data,  # None se non ancora estratta
        })
    return result


@app.get("/api/library/catalog")
async def library_catalog():
    """Restituisce il catalogo con stato di ogni entry (senza dati estratti)."""
    catalog = _load_catalog()
    return [
        {k: v for k, v in e.items() if k != "extracted"}
        for e in catalog
    ]


class LibraryAddRequest(BaseModel):
    compagnia: str
    prodotto: str
    tipo: str
    url: str | None = None
    pdf_base64: str | None = None
    filename: str | None = None


@app.post("/api/library/add")
async def library_add(req: LibraryAddRequest):
    """
    Aggiunge manualmente una polizza al catalogo.
    Se viene fornito un pdf_base64, avvia l'estrazione AI subito.
    Se viene fornito solo un URL, salva l'entry senza estrarre (estrazione on-demand).
    """
    import re as _re
    # Genera un ID univoco dal nome (slug)
    slug = _re.sub(r'[^a-z0-9]+', '-', f"{req.compagnia}-{req.prodotto}".lower()).strip('-')
    # Aggiungi timestamp per evitare duplicati
    entry_id = f"{slug}-{int(__import__('time').time())}"[-60:]

    catalog = _load_catalog()
    # Controlla duplicati per compagnia+prodotto
    existing = next((e for e in catalog if
                     e.get("compagnia","").lower() == req.compagnia.lower() and
                     e.get("prodotto","").lower() == req.prodotto.lower()), None)
    if existing:
        raise HTTPException(400, f"Polizza già presente nel catalogo: {existing['id']}")

    new_entry: dict = {
        "id": entry_id,
        "compagnia": req.compagnia,
        "prodotto": req.prodotto,
        "tipo": req.tipo,
        "url": req.url,
        "url_type": "direct" if req.url else None,
        "last_hash": None,
        "last_updated": None,
        "sync_status": "pending",
        "extracted": None,
    }

    # Se fornito un PDF, estraiamo subito
    if req.pdf_base64:
        try:
            pdf_bytes = base64.b64decode(req.pdf_base64)
            filename = req.filename or f"{req.prodotto}.pdf"
            chunks = _split_pdf_bytes(pdf_bytes, pages_per_chunk=60)
            results = await asyncio.gather(*[
                _extract_pdf_chunk_native(cb, ps, pe, pt, filename)
                for cb, ps, pe, pt in chunks
            ])
            results = [r for r in results if r]
            extracted = _merge_extractions(results) if len(results) > 1 else (results[0] if results else {})
            extracted = _sanitize_extraction(extracted)
            new_entry["extracted"] = extracted
            new_entry["last_updated"] = __import__('datetime').datetime.utcnow().isoformat()
            new_entry["sync_status"] = "updated"
            await _ensure_library_collection()
            await _q_set_library(entry_id, extracted)
        except Exception as e:
            logger.error(f"[library/add] Errore estrazione PDF per '{entry_id}': {e}")
            new_entry["sync_status"] = "error"

    catalog.append(new_entry)
    _save_catalog(catalog)
    return {"ok": True, "id": entry_id, "extracted": bool(new_entry.get("extracted"))}


@app.post("/api/library/upload-pdf")
async def library_upload_pdf(
    id: str = Form(...),
    file: UploadFile = File(...),
    request: Request = None,
):
    """
    Permette di caricare manualmente un PDF per una polizza CGA
    il cui URL è scaduto o non funzionante.
    Estrae i dati con lo stesso pipeline di _sync_entry.
    """
    _require_api_key(request)
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Solo file PDF accettati")

    pdf_bytes = await file.read()
    if len(pdf_bytes) < 500:
        raise HTTPException(status_code=400, detail="PDF troppo piccolo o corrotto")
    if len(pdf_bytes) > 20 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="PDF troppo grande (max 20 MB)")

    catalog = _load_catalog()
    entry = next((e for e in catalog if e["id"] == id), None)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Voce '{id}' non trovata nel catalogo")

    logger.info(f"[upload-pdf] '{id}' — {len(pdf_bytes)} bytes, file: {file.filename}")

    # Estrai con lo stesso pipeline di _sync_entry
    try:
        new_hash = hashlib.md5(pdf_bytes).hexdigest()
        chunks = _split_pdf_bytes(pdf_bytes, pages_per_chunk=60)
        results = await asyncio.gather(*[
            _extract_sezioni_chunk(cb, ps, pe, pt, entry.get("prodotto", id), entry.get("tipo", ""))
            for cb, ps, pe, pt in chunks
        ])
        results = [r for r in results if r]
        if not results:
            raise HTTPException(status_code=422, detail="Estrazione AI vuota — PDF illeggibile?")

        extracted = _merge_sezioni(results) if len(results) > 1 else results[0]
        extracted = _normalize_sezioni(extracted)
        extracted["_catalog_id"] = id
        extracted["_uploaded_file"] = file.filename

        # Salva in Qdrant (best-effort)
        await _q_set_library(id, extracted)

        now = __import__("datetime").datetime.utcnow().isoformat() + "Z"
        updated_entry = {
            **entry,
            "last_hash": new_hash,
            "last_updated": now,
            "sync_status": "updated",
            "sync_error": None,
            "extracted": extracted,
            "uploaded_file": file.filename,
        }
        # Aggiorna catalogo
        idx = next((i for i, e in enumerate(catalog) if e["id"] == id), None)
        if idx is not None:
            catalog[idx] = updated_entry
        _save_catalog(catalog)

        logger.info(f"[upload-pdf] '{id}' — completato ✓")
        return {"ok": True, "entries": [updated_entry]}

    except HTTPException:
        raise
    except Exception as e:
        friendly = _ai_error_message(e)
        if friendly:
            raise HTTPException(503, friendly)
        logger.error(f"[upload-pdf] '{id}' — errore: {e}")
        raise HTTPException(status_code=500, detail=str(e)[:300])


@app.post("/api/library/sync")
async def library_sync(request: Request):
    """
    Sincronizza il catalogo.
    Body opzionale: {"id": "unipol-unica-casa"} per aggiornare solo una entry.
    Senza body: sincronizza tutto.
    """
    await _ensure_library_collection()
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    catalog = _load_catalog()
    target_id = body.get("id")

    if target_id:
        entries_to_sync = [e for e in catalog if e["id"] == target_id]
        if not entries_to_sync:
            raise HTTPException(404, f"Entry '{target_id}' non trovata nel catalogo")
    else:
        entries_to_sync = catalog

    logger.info(f"[library sync] avvio sync di {len(entries_to_sync)} entry")
    updated = []
    for entry in entries_to_sync:
        result = await _sync_entry(entry)
        updated.append(result)

    # Aggiorna il catalogo su disco
    catalog_map = {e["id"]: e for e in catalog}
    for u in updated:
        catalog_map[u["id"]] = u
    _save_catalog(list(catalog_map.values()))

    stats = {
        "total": len(updated),
        "updated": sum(1 for u in updated if u.get("sync_status") == "updated"),
        "unchanged": sum(1 for u in updated if u.get("sync_status") == "unchanged"),
        "errors": sum(1 for u in updated if u.get("sync_status") == "error"),
    }
    logger.info(f"[library sync] completato: {stats}")
    return {"ok": True, "stats": stats, "entries": updated}


@app.post("/api/library/sync-stream")
async def library_sync_stream(request: Request):
    """Versione SSE di /api/library/sync — invia progress per ogni entry."""
    await _ensure_library_collection()
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    catalog = _load_catalog()
    target_id = body.get("id")
    entries_to_sync = [e for e in catalog if e["id"] == target_id] if target_id else catalog

    async def generate():
        results = []
        for i, entry in enumerate(entries_to_sync):
            pct = int((i / len(entries_to_sync)) * 90)
            prod = entry["prodotto"]
            yield f"data: {json.dumps({'type':'progress','step':f'Sync {prod}...','pct':pct})}\n\n"
            result = await _sync_entry(entry)
            results.append(result)
            yield f"data: {json.dumps({'type':'entry','data':result})}\n\n"

        # Aggiorna catalogo su disco
        catalog_map = {e["id"]: e for e in catalog}
        for u in results:
            catalog_map[u["id"]] = u
        _save_catalog(list(catalog_map.values()))

        stats = {
            "total": len(results),
            "updated": sum(1 for r in results if r.get("sync_status") == "updated"),
            "unchanged": sum(1 for r in results if r.get("sync_status") == "unchanged"),
            "errors": sum(1 for r in results if r.get("sync_status") == "error"),
        }
        yield f"data: {json.dumps({'type':'result','stats':stats})}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── FINE LIBRERIA CGA ─────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════════════════════
# ── CRON SYNC — endpoint per scheduler notturno ───────────────────────────────
# Chiamato da Railway Cron Job (o da qualsiasi scheduler) ogni notte.
# Protetto da API key per evitare accessi non autorizzati.
# ══════════════════════════════════════════════════════════════════════════════

_CRON_KEY = os.getenv("CRON_API_KEY", "")  # imposta CRON_API_KEY su Railway

@app.post("/api/cron-sync")
async def cron_sync(request: Request):
    """
    Endpoint per il cron notturno: sincronizza tutto il catalogo CGA.
    Richiede header Authorization: Bearer <CRON_API_KEY>.

    DISATTIVATO DI DEFAULT: non fa nulla (e non consuma API/crediti) a meno che
    la env var ENABLE_CRON_SYNC sia impostata a 1/true. Il catalogo si aggiorna
    a mano col pulsante "Carica PDF", quindi il sync automatico non serve.
    """
    if os.getenv("ENABLE_CRON_SYNC", "").strip().lower() not in ("1", "true", "yes"):
        logger.info("[cron-sync] disattivato (ENABLE_CRON_SYNC non impostato) — nessuna azione")
        return {"ok": False, "disabled": True,
                "msg": "Sync automatico disattivato. Le polizze si aggiornano manualmente."}

    if _CRON_KEY:
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {_CRON_KEY}":
            raise HTTPException(401, "Non autorizzato")

    logger.info("[cron-sync] avvio sync notturno catalogo CGA")
    await _ensure_library_collection()
    catalog = _load_catalog()

    results = []
    for entry in catalog:
        result = await _sync_entry(entry)
        results.append(result)

    catalog_map = {e["id"]: e for e in catalog}
    for u in results:
        catalog_map[u["id"]] = u
    _save_catalog(list(catalog_map.values()))

    stats = {
        "total": len(results),
        "updated": sum(1 for r in results if r.get("sync_status") == "updated"),
        "unchanged": sum(1 for r in results if r.get("sync_status") == "unchanged"),
        "errors": sum(1 for r in results if r.get("sync_status") == "error"),
        "errors_detail": [r["id"] for r in results if r.get("sync_status") == "error"],
    }
    logger.info(f"[cron-sync] completato: {stats}")
    return {"ok": True, "stats": stats}

# ── FINE CRON SYNC ────────────────────────────────────────────────────────────
