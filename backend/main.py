# main.py — Polizza Facile backend
import os
import anthropic
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

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
_env_origins = os.getenv("ALLOWED_ORIGINS", "*").strip()
_origins = ["*"] if _env_origins == "*" else [o.strip() for o in _env_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ── RETRY HELPER ──────────────────────────────────────────────────────────────
import asyncio, time

async def call_claude(max_retries=3, **kwargs):
    """Chiama Claude con retry automatico su errori 529 (overloaded)."""
    for attempt in range(max_retries):
        try:
            return client.messages.create(**kwargs)
        except anthropic.APIStatusError as e:
            if e.status_code == 529 and attempt < max_retries - 1:
                wait = 2 ** attempt  # 1s, 2s, 4s
                await asyncio.sleep(wait)
                continue
            raise
        except Exception:
            raise
    raise HTTPException(503, "Servizio AI temporaneamente non disponibile, riprova tra qualche secondo")


# ── MODELS ────────────────────────────────────────────────────────────────────

class ExtractRequest(BaseModel):
    text: str
    filename: str

class SummaryRequest(BaseModel):
    policies: list

class RaccomandaRequest(BaseModel):
    risposte: dict
    agenzia: str = "default"

class MatchRequest(BaseModel):
    client: dict        # {nome, answers, raccomandazioni}
    policies: list      # lista di polizze estratte dalla libreria
    feedback_history: list = []  # feedback passati rilevanti (opzionale)


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
    """Estrae struttura garanzie/franchigie/scoperti da testo di polizza."""
    if not req.text or len(req.text.strip()) < 100:
        raise HTTPException(400, "Testo polizza troppo breve o vuoto")

    text_truncated = req.text[:28000]

    prompt = f"""Sei un esperto di polizze assicurative italiane. Analizza il seguente testo estratto da una polizza e restituisci SOLO un oggetto JSON valido, nessun altro testo.

TESTO (file: {req.filename}):
---
{text_truncated}
---

Schema JSON richiesto:
{{
  "compagnia": "nome compagnia",
  "prodotto": "nome prodotto",
  "tipo": "categoria (RC Auto / Casa / Vita / Infortuni / Salute / Multirischio / altro)",
  "premio": "importo e periodicità oppure null",
  "garanzie": [
    {{
      "categoria": "Responsabilità Civile | Danni | Furto | Incendio | Infortuni | Salute | Altro",
      "nome": "nome garanzia",
      "presente": true,
      "massimale": "es: 500.000 € oppure null",
      "massimale_num": 500000,
      "franchigia": "es: 250 € oppure null",
      "scoperto": "es: 10% oppure null",
      "note": "nota breve oppure null"
    }}
  ],
  "punti_di_forza": ["punto 1", "punto 2", "punto 3"],
  "consigliata_per": "descrizione del cliente ideale in 1 frase",
  "esclusioni": ["esclusione 1", "esclusione 2"]
}}

Regole:
- massimale_num: valore numerico del massimale (0 se assente/non applicabile)
- Includi tutte le garanzie trovate nel documento
- punti_di_forza: 3 vantaggi concreti di questa polizza
- esclusioni: massimo 6, solo le più rilevanti"""

    try:
        msg = await call_claude(
            model="claude-haiku-4-5-20251001",
            max_tokens=3500,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = msg.content[0].text.strip()
        import re, json
        match = re.search(r'\{[\s\S]*\}', raw)
        if not match:
            raise HTTPException(500, "Risposta AI non valida")
        return json.loads(match.group(0))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Errore estrazione: {str(e)}")


@app.post("/api/raccomanda")
async def raccomanda(req: RaccomandaRequest):
    """Genera raccomandazioni assicurative personalizzate dal questionario."""
    import re, json as _json
    if not req.risposte:
        raise HTTPException(400, "Risposte questionario vuote")

    profile = "\n".join([f"- {k}: {v}" for k, v in req.risposte.items()])

    prompt = f"""Sei un esperto consulente assicurativo italiano. Analizza il profilo di questo cliente e genera raccomandazioni assicurative personalizzate.

PROFILO CLIENTE:
{profile}

Rispondi SOLO con un oggetto JSON valido con questa struttura:
{{
  "sintesi_profilo": "2 frasi che descrivono il profilo e i principali bisogni",
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
  "nota_consulente": "Consiglio operativo per l'agente: come approcciare questo cliente in 1-2 frasi"
}}

Regole:
- Fornisci 3–5 raccomandazioni ordinate per priorità (priorita: 1 = più urgente)
- urgenza può essere solo: alta, media, bassa
- Considera le polizze già esistenti per non duplicare coperture
- Sii concreto: motivo e cosa_cercare devono essere specifici per il profilo
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
        return _json.loads(match.group(0))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Errore raccomandazioni: {str(e)}")


@app.post("/api/match")
async def match_client_policies(req: MatchRequest):
    """Analisi incrociata cliente/polizze con punteggi di compatibilità."""
    import re, json as _json
    if not req.client or not req.policies:
        raise HTTPException(400, "Cliente e almeno una polizza sono richiesti")

    # Costruisci il profilo cliente
    answers = req.client.get("answers", {})
    recs = req.client.get("raccomandazioni", {})
    gaps = recs.get("gap_principali", []) if recs else []
    profile_lines = "\n".join([f"  - {k}: {v}" for k, v in answers.items()])
    gaps_text = "\n".join([f"  - {g}" for g in gaps]) if gaps else "  - Non disponibili"

    # Costruisci il sommario delle polizze
    policies_text = ""
    for i, p in enumerate(req.policies):
        garanzie = p.get("garanzie", [])
        g_text = ", ".join([f"{g['nome']} (max: {g.get('massimale','N/D')}, fr: {g.get('franchigia','nessuna')})"
                           for g in garanzie if g.get("presente")])
        policies_text += f"""
Polizza {i+1}: {p.get('compagnia','?')} — {p.get('prodotto','?')}
  Tipo: {p.get('tipo','?')} | Premio: {p.get('premio','N/D')}
  Garanzie attive: {g_text or 'N/D'}
  Punti di forza: {', '.join(p.get('punti_di_forza',[]))}
  Consigliata per: {p.get('consigliata_per','N/D')}
"""

    # Esempi da feedback storici rilevanti
    feedback_text = ""
    if req.feedback_history:
        feedback_text = "\n\nESEMPI DA CASI PRECEDENTI SIMILI (usa per calibrare):\n"
        for fb in req.feedback_history[:5]:
            feedback_text += f"  - Profilo simile ({fb.get('clientType','?')}): {fb.get('note','')}" \
                           f" → Polizza scelta: {fb.get('chosenPolicy','?')} | Rating: {fb.get('rating','?')}/5\n"

    prompt = f"""Sei un esperto consulente assicurativo italiano di Polo Assicurativo Bassano.
Analizza la compatibilità tra il profilo di questo cliente e le polizze disponibili.

PROFILO CLIENTE — {req.client.get('nome','Cliente')}:
{profile_lines}

GAP ASSICURATIVI IDENTIFICATI:
{gaps_text}
{feedback_text}
POLIZZE DA VALUTARE:
{policies_text}

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
  "top_recommendation": "Spiegazione in 2-3 frasi di quale polizza consigliare e perché, con riferimento ai bisogni specifici del cliente",
  "agent_tip": "Consiglio pratico per l'agente su come presentare la proposta a questo cliente"
}}

Regole:
- compatibility_score: 0-100, quanto la polizza copre i bisogni di QUESTO specifico cliente
- gap_coverage: analizza ogni gap identificato contro le garanzie della polizza
- ranking: array di policy_index ordinati dal più al meno adatto (0=primo in lista)
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
        return _json.loads(match.group(0))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Errore match: {str(e)}")


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

    prompt = f"""Sei un consulente assicurativo italiano. Confronta queste polizze e scrivi un paragrafo di 3-4 frasi in italiano chiaro, pensato per un cliente non esperto. Evidenzia la differenza principale, quale offre la copertura più ampia e quando conviene scegliere l'una o l'altra. Sii diretto e pratico, evita il gergo tecnico.

POLIZZE:
{brief}

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
        raise HTTPException(500, f"Errore riepilogo: {str(e)}")
