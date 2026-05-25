# main.py — Polizza Facile backend
import os
import re
import json
import asyncio
import logging
import anthropic
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from qdrant_client import AsyncQdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

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

# ── QDRANT — PERSISTENZA DATI ─────────────────────────────────────────────────
QDRANT_URL        = os.getenv("QDRANT_URL", "")
QDRANT_API_KEY    = os.getenv("QDRANT_API_KEY", "")
QDRANT_COLLECTION = "polizza_facile_data"

# ID fissi per i tre "documenti" nella collezione
_CLIENTS_PID = "00000000-0000-0000-0000-000000000001"
_POLIZZE_PID = "00000000-0000-0000-0000-000000000002"
_CONFIG_PID  = "00000000-0000-0000-0000-000000000003"
_DUMMY_VEC   = [0.0]

_qdrant: AsyncQdrantClient | None = None


@app.on_event("startup")
async def _startup():
    global _qdrant
    if not QDRANT_URL:
        logger.warning("QDRANT_URL non configurato — persistenza Qdrant disabilitata")
        return
    try:
        _qdrant = AsyncQdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY or None)
        cols = await _qdrant.get_collections()
        names = [c.name for c in cols.collections]
        if QDRANT_COLLECTION not in names:
            await _qdrant.create_collection(
                QDRANT_COLLECTION,
                vectors_config=VectorParams(size=1, distance=Distance.COSINE)
            )
            logger.info(f"Qdrant: collezione '{QDRANT_COLLECTION}' creata")
        else:
            logger.info(f"Qdrant: collezione '{QDRANT_COLLECTION}' trovata — ok")
    except Exception as e:
        logger.error(f"Qdrant init fallito: {e}")
        _qdrant = None


async def _q_get(point_id: str):
    """Legge il payload di un punto dalla collezione Qdrant."""
    if not _qdrant:
        return None
    try:
        res = await _qdrant.retrieve(QDRANT_COLLECTION, ids=[point_id], with_payload=True)
        return res[0].payload.get("data") if res else None
    except Exception as e:
        logger.error(f"Qdrant get {point_id}: {e}")
        return None


async def _q_set(point_id: str, data):
    """Salva (upsert) un payload nella collezione Qdrant."""
    if not _qdrant:
        return
    try:
        await _qdrant.upsert(
            QDRANT_COLLECTION,
            points=[PointStruct(id=point_id, vector=_DUMMY_VEC, payload={"data": data})]
        )
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
- "Decesso da infortunio"
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
      "massimale": "importo scritto nel documento es: 500.000 € — oppure null se non trovato",
      "massimale_num": 500000,
      "franchigia": "es: 250 € o 5% — oppure null",
      "scoperto": "es: 10% — oppure null",
      "note": "informazione rilevante breve (es: valida in tutto il mondo, solo ricovero >3gg) oppure null"
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
- presente: true se la garanzia è inclusa nel pacchetto base; false altrimenti
- opzionale: true se è un supplemento acquistabile a pagamento; false se è completamente assente dal prodotto
- Includi TUTTE le garanzie menzionate nel testo, anche quelle opzionali
- punti_di_forza: 3 vantaggi concreti e specifici, NON generici
- esclusioni: massimo 6, solo le più rilevanti per un cliente medio
- Se il testo è parziale (brochure, DIP), estrai comunque tutto il possibile"""


async def _extract_single_chunk(text_chunk: str, filename: str, chunk_info: str = "") -> dict:
    """Estrae dati strutturati da un singolo chunk di testo polizza."""
    prompt = _build_extraction_prompt(text_chunk, filename, chunk_info)
    msg = await call_claude(
        model="claude-sonnet-4-6",
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}]
    )
    raw = msg.content[0].text.strip()
    match = re.search(r'\{[\s\S]*\}', raw)
    if not match:
        raise ValueError("JSON non trovato nella risposta")
    return json.loads(match.group(0))


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
                if new_mass > ex_mass:
                    all_garanzie[nome] = g
                elif new_mass == ex_mass:
                    # Preferisce il record con più campi valorizzati
                    if sum(1 for v in g.values() if v not in (None, 0, "")) > \
                       sum(1 for v in existing.values() if v not in (None, 0, "")):
                        all_garanzie[nome] = g

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


# ── ENDPOINTS ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "polizza-facile"}

@app.get("/", response_class=HTMLResponse)
async def serve_app():
    """Serve il frontend direttamente dal backend."""
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), headers={
            "Cache-Control": "no-cache, no-store, must-revalidate"
        })


@app.post("/api/extract")
async def extract_policy(req: ExtractRequest):
    """
    Estrae struttura garanzie/franchigie/scoperti da testo di polizza.
    Per documenti lunghi (>50.000 caratteri) divide in chunk sovrapposti
    ed estrae in parallelo, poi unisce i risultati.
    """
    text = req.text.strip() if req.text else ""
    if len(text) < 100:
        raise HTTPException(400, "Testo polizza troppo breve o vuoto")

    CHUNK_SIZE = 50_000   # caratteri per chunk
    OVERLAP    =  3_000   # sovrapposizione tra chunk consecutivi
    MAX_CHUNKS =      3   # massimo 3 chunk → copertura fino a ~144.000 caratteri

    try:
        if len(text) <= CHUNK_SIZE:
            # Documento breve: singola estrazione
            result = await _extract_single_chunk(text, req.filename)
        else:
            # Documento lungo: chunking con overlap, estrazione parallela
            chunks = []
            start = 0
            while start < len(text) and len(chunks) < MAX_CHUNKS:
                end = min(start + CHUNK_SIZE, len(text))
                chunks.append(text[start:end])
                if end == len(text):
                    break
                start += CHUNK_SIZE - OVERLAP

            total = len(chunks)
            logger.info(f"[extract] '{req.filename}' → {total} chunk(s), {len(text)} chars totali")

            chunk_infos = [f"parte {i+1} di {total}" for i in range(total)]
            results = await asyncio.gather(*[
                _extract_single_chunk(chunks[i], req.filename, chunk_infos[i])
                for i in range(total)
            ])
            result = _merge_extractions(list(results))

        return result

    except HTTPException:
        raise
    except json.JSONDecodeError:
        logger.error("JSON parse error in /api/extract")
        raise HTTPException(500, "Formato dati non valido — riprova")
    except Exception as e:
        logger.error(f"Error in /api/extract: {e}")
        raise HTTPException(500, "Errore durante l'analisi della polizza")


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
