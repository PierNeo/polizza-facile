# main.py — Polizza Facile backend
import os
import re
import json
import asyncio
import logging
import base64
import io
import anthropic
import httpx
from pypdf import PdfReader, PdfWriter
from fastapi import FastAPI, HTTPException, Request
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
# Default vuoto = nessuna origine ammessa se .env non è configurato (sicuro per produzione)
_env_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
if _env_origins == "*":
    _origins = ["*"]
elif _env_origins:
    _origins = [o.strip() for o in _env_origins.split(",") if o.strip()]
else:
    _origins = []  # sicuro: nessun accesso cross-origin di default

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── CLIENT ANTHROPIC (ASYNC) ──────────────────────────────────────────────────
client = anthropic.AsyncAnthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ── QDRANT — PERSISTENZA DATI (via REST API dirette) ──────────────────────────
# Usiamo httpx invece del client qdrant-client per maggiore affidabilità e
# visibilità degli errori. Nessuna dipendenza da librerie esterne aggiuntive.

QDRANT_URL        = os.getenv("QDRANT_URL", "").rstrip("/")
QDRANT_API_KEY    = os.getenv("QDRANT_API_KEY", "")
QDRANT_COLLECTION = "polizza_facile_data"

# ID fissi UUID per i tre "documenti" nella collezione
_CLIENTS_PID = "00000000-0000-0000-0000-000000000001"
_POLIZZE_PID = "00000000-0000-0000-0000-000000000002"
_CONFIG_PID  = "00000000-0000-0000-0000-000000000003"

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


async def _q_set(point_id: str, data):
    """Salva (upsert) un punto Qdrant via REST."""
    if not QDRANT_URL or not _qdrant_ok:
        return
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            r = await http.put(
                f"{QDRANT_URL}/collections/{QDRANT_COLLECTION}/points",
                headers=_qh(),
                json={"points": [{"id": point_id, "vector": [0.0], "payload": {"data": data}}]}
            )
            r.raise_for_status()
    except Exception as e:
        logger.error(f"Qdrant set {point_id}: {e}")


# ── ENDPOINTS DATI PERSISTENTI ────────────────────────────────────────────────

@app.get("/api/clients")
async def api_get_clients():
    data = await _q_get(_CLIENTS_PID)
    return data if data is not None else []

@app.post("/api/clients")
async def api_save_clients(req: Request):
    body = await req.json()
    await _q_set(_CLIENTS_PID, body.get("data", []))
    return {"ok": True}

@app.get("/api/polizze")
async def api_get_polizze():
    data = await _q_get(_POLIZZE_PID)
    return data if data is not None else []

@app.post("/api/polizze")
async def api_save_polizze(req: Request):
    body = await req.json()
    await _q_set(_POLIZZE_PID, body.get("data", []))
    return {"ok": True}

@app.get("/api/config")
async def api_get_config():
    data = await _q_get(_CONFIG_PID)
    return data if data is not None else {}

@app.post("/api/config")
async def api_save_config(req: Request):
    body = await req.json()
    await _q_set(_CONFIG_PID, body.get("data", {}))
    return {"ok": True}

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
    # Garanzie casa con sublimiti mancanti nelle note
    garanzie_note_incomplete = [
        g["nome"] for g in merged.get("garanzie", [])
        if not g.get("note") or ("Sublimiti" not in (g.get("note") or "") and g.get("nome") in [
            "Furto e rapina in casa", "Incendio e danni alla proprietà",
            "Responsabilità civile verso terzi", "Assistenza casa",
            "Terremoto", "Alluvione e inondazione"
        ])
    ]
    # Garanzie infortuni con scoperto o franchigia in giorni mancante
    garanzie_infortuni_da_completare = [
        g["nome"] for g in merged.get("garanzie", [])
        if g.get("nome") in [
            "Rimborso spese mediche", "Diaria per inabilità temporanea al lavoro",
            "Diaria da ricovero", "Diaria post ricovero", "Diaria da immobilizzazione",
            "Invalidità permanente da infortunio", "Rendita vitalizia"
        ] and (not g.get("scoperto") or not g.get("franchigia"))
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
   - ASSISTENZA CASA (CRITICO): cerca nella sezione "Assistenza Casa", "Pronto Intervento" o nella tabella "SINTESI DEI LIMITI DI INDENNIZZO" i limiti per tipo di servizio. I valori variano da polizza a polizza — usa SEMPRE i valori ESATTI trovati nel testo. Scrivi nel campo note tutti i sublimiti trovati: "Sublimiti: Artigiani max €X/evento | Asciugatura max €Y/evento | Vigilanza max N ore | Deposito max €Z/evento | ...". Cerca pattern "massimo" o "fino a" seguiti da un importo in Euro vicino a "intervento", "artigiano", "idraulico", "asciugatura", "vigilanza", "pernottamento".
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
        model="claude-sonnet-4-6",
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
— ASSISTENZA CASA: cerca "SINTESI DEI LIMITI" o i singoli articoli per trovare il limite ESATTO per tipo di servizio (varia da polizza a polizza). Scrivi in note tutti i sublimiti trovati: "Sublimiti: Artigiani max €X/evento | Asciugatura max €Y/evento | Vigilanza max N ore | Deposito max €Z/evento | ..." — usa i valori ESATTI del testo, non inventare cifre.
— POLIZZE INFORTUNI — "MORTE DA INFORTUNI" (o "Decesso da infortuni"): alcuni prodotti (es. Tandem) usano "Morte" invece di "Decesso". Mappala SEMPRE alla tassonomia come "Decesso da infortuni".
— POLIZZE INFORTUNI: massimale = "Somma assicurata". Leggi la TABELLA RIASSUNTIVA DI LIMITI per scoperti (es: "20% min. €75") e franchigie in giorni (es: "5/10/15 giorni in base alla diaria scelta")
— scoperto: includi SEMPRE il minimo in € (es: "10% min. €250", non solo "10%")
— esclusioni: MAX 6, solo le più sorprendenti/rilevanti per un cliente normale
— opzionale=true per garanzie acquistabili a pagamento, presente=false se assente dalla base
— NON inventare valori: se non trovi una cifra specifica, usa null/0"""

    try:
        msg = await client.messages.create(
            model="claude-opus-4-6",
            max_tokens=4096,
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
async def serve_app():
    """Serve il frontend direttamente dal backend."""
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), headers={
            "Cache-Control": "no-cache, no-store, must-revalidate"
        })

@app.get("/nicolo", response_class=HTMLResponse)
async def serve_nicolo():
    """Serve il comparatore personalizzato per Nicolò Prior (Allianz Rosa)."""
    html_path = os.path.join(os.path.dirname(__file__), "nicolo.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), headers={
            "Cache-Control": "no-cache, no-store, must-revalidate"
        })


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
        msg = await client.messages.create(
            model="claude-sonnet-4-6",
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
            model="claude-haiku-4-5-20251001",
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
            model="claude-sonnet-4-6",
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
            model="claude-haiku-4-5-20251001",
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
            "invalidità permanente grave da infortuni",
        ],
        "sotto_garanzie": [],
    },
    "rss_infortuni": {
        "id": "rss_infortuni",
        "nome_standard": "Rimborso spese sanitarie da infortuni",
        "sinonimi": [
            "rimborso spese mediche", "rimborso spese di cura",
            "spese sanitarie", "spese di cura", "rss",
            "rimborso spese", "rimborso spese mediche da infortuni",
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
            "diaria post ricovero", "diaria per ricovero",
            "diaria da ricovero completa",
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
        ],
        "sotto_garanzie": [],
    },
    "rendita_vitalizia": {
        "id": "rendita_vitalizia",
        "nome_standard": "Rendita vitalizia",
        "sinonimi": ["rendita vitalizia", "rendita"],
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


# ── TOOL USE SCHEMA PER SEZIONI ───────────────────────────────────────────────

def _sezione_schema(tipo_polizza: str) -> dict:
    """Tool use schema per estrazione a sezioni. Cambia in base al tipo polizza."""

    if tipo_polizza == "Casa":
        sezioni_enum = [d["nome_standard"] for d in SINONIMI_SEZIONI_CASA.values()]
        sotto_garanzie_desc = """
Oggetto con le sotto-garanzie della sezione. Per INCENDIO: incendio_fulmine_scoppio, eventi_atmosferici,
atti_vandalici, danni_acqua, rottura_lastre, ricerca_guasto, spese_demolizione.
Per FURTO: furto, rapina, scippo, gioielli_preziosi, denaro_valori, furto_fuori_casa.
Per RC: vita_privata, proprieta_fabbricato, conduzione_alloggi, figli_minori, animali_domestici.
Per ASSISTENZA: artigiani, asciugatura, vigilanza, deposito_contenuto, pernottamento.
"""
    else:  # Infortuni
        sezioni_enum = [d["nome_standard"] for d in SINONIMI_SEZIONI_INFORTUNI.values()]
        sotto_garanzie_desc = "Non applicabile per infortuni — lascia null."

    return {
        "name": "extract_sezioni",
        "description": f"Estrae la struttura a sezioni di una polizza assicurativa italiana di tipo {tipo_polizza}.",
        "input_schema": {
            "type": "object",
            "properties": {
                "compagnia":  {"type": ["string", "null"]},
                "prodotto":   {"type": ["string", "null"]},
                "tipo":       {"type": "string", "enum": ["RC Auto", "Casa", "Vita", "Infortuni", "Salute", "Multirischio", "Risparmio", "altro"]},
                "premio":     {"type": ["string", "null"]},
                "sezioni": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id":           {"type": "string", "description": "ID normalizzato (snake_case): incendio, furto, rc, assistenza, tutela_legale, terremoto_alluvione, fotovoltaico, morte, ip_infortuni, rss_infortuni, diaria_gesso, diaria_ricovero, diaria_inabilita, ip_malattia, rendita_vitalizia"},
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
    tipo_note = f"\nNOTA: questa polizza è probabilmente di tipo '{tipo_hint}'.\n" if tipo_hint else ""

    sinonimi_casa_txt = "\n".join(
        f"  • '{d['nome_standard']}' (id: {sid}) — sinonimi: {', '.join(d['sinonimi'][:5])}"
        for sid, d in SINONIMI_SEZIONI_CASA.items()
    )
    sinonimi_infortuni_txt = "\n".join(
        f"  • '{d['nome_standard']}' (id: {sid}) — sinonimi: {', '.join(d['sinonimi'][:5])}"
        for sid, d in SINONIMI_SEZIONI_INFORTUNI.items()
    )

    return f"""Sei un esperto di polizze assicurative italiane. Analizza questo documento (file: {filename}) e usa la funzione extract_sezioni.
{tipo_note}

DIZIONARIO SINONIMI — le compagnie usano nomi diversi per le stesse sezioni. Usa questo mapping per riconoscere le sezioni e normalizzare al nome standard:

POLIZZE CASA:
{sinonimi_casa_txt}

POLIZZE INFORTUNI:
{sinonimi_infortuni_txt}

REGOLE CRITICHE:
— id e nome: usa SEMPRE i valori standard dal dizionario sopra. Es: "Morte da infortuni" di Tandem → id="morte", nome="Morte da infortuni"
— POLIZZE INFORTUNI: distingui "assistenza_sanitaria" (id=assistenza_sanitaria, per infortuni/salute — infermiere, fisioterapista, rimpatrio) da "assistenza" (id=assistenza, solo per polizze Casa — idraulico, vetraio, fabbro). Per polizze Infortuni usa SEMPRE id="assistenza_sanitaria".
— POLIZZE MODULARI (es. Tandem): anche se una garanzia richiede attivazione specifica nella scheda, se è descritta nel testo come garanzia della sezione Infortuni mettila come inclusa=false, opzionale=true. NON metterla assente se è chiaramente descritta nel documento.
— TUTELA LEGALE nelle polizze CASA: se nel testo c'è una sezione "Tutela Legale" con le sue condizioni (massimale, articoli, carenza), mettila come inclusa=true anche se il massimale è variabile o "indicato in polizza". La presenza della sezione nel contratto = garanzia inclusa.
— MASSIMALE "Indicato in Polizza" o "Variabile": se il testo dice che il massimale è scelto dal contraente o indicato in polizza, usa massimale="Indicato in Polizza" e inclusa=true (non opzionale).
— "Morte da infortuni" / "7.1 Morte da infortuno": se presente nel testo della polizza (anche come sezione 7.1), estraila sempre. Per Tandem è una garanzia della sezione Infortuni → id="morte", inclusa=true (o opzionale=true se modulare).
— massimale: per Incendio/Furto/Infortuni usa "Somma assicurata". Per RC cerca il valore fisso (es: €5.000.000). Se il testo dice "massimale indicato in polizza" usa "Indicato in Polizza" e massimale_num=0.
— franchigia e scoperto: estrai SEMPRE con il minimo in € quando presente (es: "10% min. €250"). Per infortuni cerca la tabella riassuntiva.
— sublimiti: formato "Voce max €X | Voce max €Y". Per Furto: gioielli, valori, scippo fuori. Per Assistenza sanitaria: limiti per tipo prestazione (infermiere, fisioterapista, rimpatrio, ecc.).
— sotto_garanzie: per Casa indica quali sotto-garanzie sono incluse (true/false) o il loro valore (es: "max €15.000" per gioielli).
— Se una sezione è ESCLUSA esplicitamente: inclusa=false, opzionale=false. Se è opzionale acquistabile: inclusa=false, opzionale=true.
— Estrai TUTTE le sezioni presenti o esplicitamente escluse."""


# ── MODELLO REQUEST ───────────────────────────────────────────────────────────

class ExtractSezioniRequest(BaseModel):
    pdf_base64: str
    filename: str
    tipo_hint: str = ""  # "Casa" | "Infortuni" | "" (auto)


# ── CORE EXTRACTION FUNCTION ──────────────────────────────────────────────────

async def _extract_sezioni_chunk(chunk_bytes: bytes, page_start: int, page_end: int,
                                  total_pages: int, filename: str, tipo_hint: str) -> dict:
    """Estrae sezioni da un chunk PDF usando Claude native PDF + tool use."""
    chunk_b64 = base64.b64encode(chunk_bytes).decode()
    chunk_info = f"pagine {page_start + 1}-{page_end} di {total_pages}"
    prompt = _build_sezioni_prompt(filename, tipo_hint) + f"\n\n(stai analizzando {chunk_info})"

    # Prima chiamata senza tipo per rilevarlo, poi con schema corretto
    tipo_per_schema = tipo_hint if tipo_hint else "Casa"  # default Casa, poi merge decide

    try:
        msg = await client.messages.create(
            model="claude-opus-4-6",
            max_tokens=4096,
            tools=[_sezione_schema(tipo_per_schema)],
            tool_choice={"type": "tool", "name": "extract_sezioni"},
            messages=[{
                "role": "user",
                "content": [
                    {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": chunk_b64}},
                    {"type": "text", "text": prompt}
                ]
            }]
        )
        for block in msg.content:
            if block.type == "tool_use":
                return block.input
        return {}
    except Exception as e:
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
                def _score(x): return sum(1 for v in x.values() if v not in (None, 0, "", False))
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
    Se il modello ha usato un nome non standard, lo corregge.
    """
    tipo = result.get("tipo", "Casa")
    syn_index = _SYN_INFORTUNI if tipo == "Infortuni" else _SYN_CASA
    sezioni_map = SINONIMI_SEZIONI_INFORTUNI if tipo == "Infortuni" else SINONIMI_SEZIONI_CASA

    for s in result.get("sezioni", []):
        nome = (s.get("nome") or "").lower().strip()
        # Cerca nel dizionario sinonimi
        matched_id = syn_index.get(nome)
        if matched_id and matched_id in sezioni_map:
            s["id"] = matched_id
            s["nome"] = sezioni_map[matched_id]["nome_standard"]
        elif not s.get("id"):
            # Genera un id snake_case dal nome
            s["id"] = re.sub(r'[^a-z0-9]+', '_', nome)[:30].strip('_')

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

    # Cache
    cache_key = _cache_key(req.pdf_base64[:2000] + str(len(pdf_bytes)) + "v3sezioni")
    if cache_key in _extraction_cache:
        logger.info(f"[sezioni] '{req.filename}' — cache hit")
        return _extraction_cache[cache_key]

    try:
        chunks = _split_pdf_bytes(pdf_bytes, pages_per_chunk=60)
        total = len(chunks)
        logger.info(f"[sezioni] '{req.filename}' → {total} chunk(s), {len(pdf_bytes)//1024}KB")

        results = await asyncio.gather(*[
            _extract_sezioni_chunk(cb, ps, pe, pt, req.filename, req.tipo_hint)
            for cb, ps, pe, pt in chunks
        ])
        results = [r for r in results if r]
        if not results:
            raise HTTPException(500, "Nessun dato estratto dal PDF")

        result = _merge_sezioni(results) if len(results) > 1 else results[0]
        result = _normalize_sezioni(result)
        _extraction_cache[cache_key] = result
        return result

    except HTTPException:
        raise
    except Exception as e:
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

                results = await asyncio.gather(*[
                    _extract_sezioni_chunk(cb, ps, pe, pt, req.filename, req.tipo_hint)
                    for cb, ps, pe, pt in chunks
                ])
                await queue.put({"type": "progress", "step": "Normalizzazione sezioni...", "pct": 80})

                results = [r for r in results if r]
                if not results:
                    await queue.put({"type": "error", "message": "Nessun dato estratto dal PDF"})
                    return

                result = _merge_sezioni(results) if len(results) > 1 else results[0]
                await queue.put({"type": "progress", "step": "Applicazione dizionario sinonimi...", "pct": 92})
                result = _normalize_sezioni(result)
                _extraction_cache[cache_key] = result
                await queue.put({"type": "result", "data": result})

            except Exception as e:
                logger.error(f"[sezioni stream] errore '{req.filename}': {e}")
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

_CATALOG_PATH = pathlib.Path(__file__).parent / "cga_catalog.json"
_LIBRARY_COLLECTION = "cga_library"
_LIBRARY_PID_PREFIX = "lib:"  # es: "lib:unipol-unica-casa"


def _load_catalog() -> list[dict]:
    """Legge il catalogo da file JSON."""
    if not _CATALOG_PATH.exists():
        return []
    with open(_CATALOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_catalog(catalog: list[dict]):
    """Salva il catalogo aggiornato su file."""
    with open(_CATALOG_PATH, "w", encoding="utf-8") as f:
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

    try:
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as http:
            r = await http.get(url, headers={"User-Agent": "Mozilla/5.0 (compatible; PFBot/1.0)"})
            if r.status_code != 200:
                logger.warning(f"[library sync] '{entry_id}' — HTTP {r.status_code}")
                return {**entry, "sync_status": "error", "sync_error": f"HTTP {r.status_code}"}
            pdf_bytes = r.content

        if len(pdf_bytes) < 500:
            return {**entry, "sync_status": "error", "sync_error": "PDF troppo piccolo"}

        # Hash del PDF
        new_hash = hashlib.md5(pdf_bytes).hexdigest()
        old_hash = entry.get("last_hash")

        if new_hash == old_hash:
            logger.info(f"[library sync] '{entry_id}' — nessun cambiamento (hash identico)")
            return {**entry, "sync_status": "unchanged"}

        # Hash diverso → ri-estrae
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

        # Salva in Qdrant
        await _q_set_library(entry_id, extracted)

        # Aggiorna entry con nuovo hash e timestamp
        now = __import__("datetime").datetime.utcnow().isoformat() + "Z"
        updated_entry = {
            **entry,
            "last_hash": new_hash,
            "last_updated": now,
            "sync_status": "updated",
            "sync_error": None,
        }
        logger.info(f"[library sync] '{entry_id}' — completato ✓")
        return updated_entry

    except Exception as e:
        logger.error(f"[library sync] '{entry_id}' — errore: {e}")
        return {**entry, "sync_status": "error", "sync_error": str(e)[:200]}


# ── ENDPOINTS LIBRERIA ────────────────────────────────────────────────────────

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
    Richiede header Authorization: Bearer <CRON_API_KEY>
    """
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
