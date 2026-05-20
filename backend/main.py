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

# ── CORS (solo per sviluppo locale / eventuali client esterni) ────────────────
_env_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
if _env_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in _env_origins.split(",") if o.strip()],
        allow_methods=["*"],
        allow_headers=["*"],
    )

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


# ── MODELS ────────────────────────────────────────────────────────────────────

class ExtractRequest(BaseModel):
    text: str
    filename: str

class SummaryRequest(BaseModel):
    policies: list

class RaccomandaRequest(BaseModel):
    risposte: dict
    agenzia: str = "default"


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
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=3500,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = msg.content[0].text.strip()
        # Estrai JSON anche se Claude aggiunge testo
        import re, json
        match = re.search(r'\{[\s\S]*\}', raw)
        if not match:
            raise HTTPException(500, "Risposta AI non valida")
        return json.loads(match.group(0))
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
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = msg.content[0].text.strip()
        match = re.search(r'\{[\s\S]*\}', raw)
        if not match:
            raise HTTPException(500, "Risposta AI non valida")
        return _json.loads(match.group(0))
    except Exception as e:
        raise HTTPException(500, f"Errore raccomandazioni: {str(e)}")


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
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}]
        )
        return {"summary": msg.content[0].text.strip()}
    except Exception as e:
        raise HTTPException(500, f"Errore riepilogo: {str(e)}")
