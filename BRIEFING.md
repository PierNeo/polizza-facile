# Polizza Facile — Briefing per UI/Layout

## Cos'è

**Polizza Facile** è un tool SaaS di confronto polizze assicurative con AI, sviluppato per **Polo Assicurativo Bassano** (broker assicurativo). Permette agli agenti di confrontare fino a 4 polizze contemporaneamente, con estrazione automatica delle garanzie tramite Claude AI.

URL produzione: `https://polizza-facile-git-main-pierneos-projects.vercel.app`

---

## Obiettivo del prodotto

Dare agli agenti assicurativi uno strumento professionale per:
1. **Confrontare polizze** di compagnie diverse fianco a fianco (tabella comparativa)
2. **Estrarre automaticamente** garanzie, massimali, franchigie e sublimiti dai PDF ufficiali (CGA)
3. **Analizzare con AI** i punti di forza e debolezza di ogni polizza rispetto al profilo cliente
4. **Gestire una libreria** di polizze personali + un database CGA di ~61 polizze pre-caricate

---

## Architettura tecnica

| Layer | Tecnologia | Dove |
|-------|-----------|------|
| Frontend | HTML/CSS/JS **single file** | `frontend/index.html` (4.589 righe) |
| Backend | FastAPI Python | `backend/main.py` (2.880 righe) |
| Catalogo CGA | JSON | `backend/cga_catalog.json` (61 polizze) |
| Deploy frontend | Vercel | auto-deploy da GitHub main |
| Deploy backend | Railway | `polizza-facile-production.up.railway.app` |
| AI estrazione | Claude API (claude-opus-4-5) | nel backend |
| Vettoriale (futuro) | Qdrant | già connesso in Railway |

> ⚠️ **IMPORTANTE**: il frontend è un **singolo file HTML** — tutto CSS, JS e HTML è dentro `frontend/index.html`. Non ci sono file separati per CSS o JS.

---

## Struttura del frontend (index.html)

Il file è diviso in sezioni logiche con commenti `/* ── SECTION ── */`:

### CSS (righe ~12–800)
- Variabili brand: `--polo` (blu scuro #0A1F35), `--gold` (#C8971C)
- Palette app: `--blue`, `--green`, `--red`, `--orange`
- Font: Inter (Google Fonts)
- Componenti: topnav, sidebar, cards, tabelle, modali, badge

### HTML (righe ~800–1.100)
- **Topnav**: logo + nav (Dashboard, Polizze, Clienti, Questionario) + barra confronto + bottone Confronta
- **Sidebar**: filtri categoria (Casa, Infortuni, RC Auto, Vita, Salute) + Vista (Tutte/Le mie/Database CGA)
- **Main content**: area dinamica con 4 pagine (dashboard, libreria, confronto, clienti)

### JavaScript (righe ~1.100–4.589)
- `renderDashboard()` — stat cards + activity feed
- `renderLibreria()` — griglia polizze con filtri
- `renderConfronto()` — tabella comparativa + AI analysis box
- `buildTableSezioni()` — costruisce la tabella di confronto dalle garanzie estratte
- `callExtract()` — chiama il backend per estrarre dati da PDF
- `renderQuestionario()` — profilo cliente

---

## Pagine dell'app

### 1. Dashboard
Panoramica con: totale polizze, clienti, categorie, feed attività recente.

### 2. Polizze (pagina principale)
- **Vista "Tutte"**: polizze caricate dall'agente (card con compagnia, prodotto, categoria, data)
- **Vista "Le mie"**: filtro per polizze personali
- **Vista "Database CGA"**: catalogo pre-caricato di ~61 polizze ufficiali, divise per categoria
- **Barra confronto** (topnav): mostra le polizze selezionate (max 4) + bottone Confronta
- **Upload PDF**: drag & drop o click per caricare nuove polizze

### 3. Confronto
- **Tabella dettaglio**: righe = garanzie (Incendio, Furto, RC, Assistenza, ecc.), colonne = polizze
- **Analisi AI**: box con analisi testuale generata da Claude
- **Tab "Consigliata per"**: profilo cliente ideale per ogni polizza
- I campi `—` significano garanzia assente (non mancante — è stato verificato)

### 4. Clienti / Questionario
Profilo cliente per raccomandazioni personalizzate.

---

## Categorie polizze

| Categoria | Polizze in catalogo | Stato |
|-----------|-------------------|-------|
| Casa | 28 | ✅ Completo, estrazione verificata |
| Infortuni | 22 | ✅ Completo, estrazione verificata |
| RC Auto | 11 | ✅ Appena aggiunto (UnipolSai, Generali, AXA, Allianz, Linear, Sara, Zurich, HDI, Groupama, Cattolica, Reale Mutua) |
| Vita | 2 | 🔄 Parziale |
| Salute | 0 | 📋 Da aggiungere |

---

## Palette colori brand

```css
--polo: #0A1F35        /* blu notte — colore principale brand */
--polo-mid: #152D4A    /* blu medio */
--polo-light: #1E3E60  /* blu chiaro */
--gold: #C8971C        /* oro — accento principale */
--gold-soft: #FDF5DC   /* oro pallido — background accenti */
--blue: #0066CC        /* azione/link */
--green: #1D8348       /* presente/successo */
--red: #C0392B         /* assente/errore */
--orange: #E67E22      /* opzionale/warning */
```

---

## File da leggere per capire il progetto

| File | Cosa contiene |
|------|--------------|
| `frontend/index.html` | Tutto il frontend (HTML + CSS + JS) |
| `backend/main.py` | API FastAPI, pipeline estrazione AI, prompt |
| `backend/cga_catalog.json` | Catalogo 61 polizze con URL PDF ufficiali |

---

## Note tecniche importanti

- **API Key**: il frontend manda header `X-API-Key` a ogni richiesta backend
- **Estrazione**: il backend divide il PDF in chunk da 60 pagine, li processa in parallelo con Claude, poi fa merge dei risultati
- **Cache**: i risultati di estrazione sono cachati in memoria (Railway) per evitare ri-estrazioni
- **CORS**: il backend accetta richieste da Vercel + localhost
- **Volume Railway**: i PDF scaricati sono cachati su `/data` (volume persistente Railway)

---

*Documento generato il 10 giugno 2026*
