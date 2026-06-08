/**
 * config.js — Configurazione agenzia per Polizza Facile
 * -------------------------------------------------------
 * Per personalizzare l'app per una nuova agenzia,
 * modifica SOLO questo file. Non toccare index.html.
 *
 * Poi includi questo file PRIMA di index.html:
 *   <script src="config.js"></script>
 */

window.AGENZIA_CONFIG = {

  // ── IDENTITÀ ──────────────────────────────────────────────────────────────
  nome:        "Polo Assicurativo Bassano",
  nomeBreve:   "Polo Assicurativo",          // usato nella sidebar mobile
  nomeSpan:    "Assicurativo",               // parte colorata nel logo testuale
  tagline:     "Progettiamo la tua protezione",
  sito:        "polobassano.it",
  email:       "info@polobassano.it",
  indirizzo:   "Via S. Pio X 58/3 · Cassola (VI)",
  agente:      "",                           // es: "Mario Rossi" — agente specifico

  // ── LOGO ──────────────────────────────────────────────────────────────────
  // URL immagine logo (bianco su sfondo scuro). Lascia "" per usare il logo testuale.
  logoUrl: "https://www.polobassano.it/wp-content/uploads/2023/04/Polo_-Assicurativo_Bassano_logo_white.png",

  // ── BRAND COLORS ──────────────────────────────────────────────────────────
  // Colori principali dell'agenzia (sidebar, bottoni, accenti)
  colori: {
    primario:     "#0F2741",   // sidebar, bottoni principali
    primarioMid:  "#1A3D60",   // hover bottoni
    primarioLight:"#234E7A",   // gradiente hero
    accento:      "#C8971C",   // badge, evidenziazioni, active nav
    accentoSoft:  "#FDF5DC",   // sfondi soft
    accentoMid:   "#E8C050",   // testo accento chiaro
    accentoDark:  "#A07810",   // hover accento
  },

  // ── API ───────────────────────────────────────────────────────────────────
  // URL del backend. In produzione metti l'URL Railway/Render.
  backendUrl:  "https://polizza-facile-production.up.railway.app",
  apiKey:      "zMf0NH5qm80VXa6UXi26NQAUh0E20V9v",

  // ── V2 EXTRACTION (solo branch v2-native-pdf) ────────────────────────────
  // true  = Claude legge il PDF visivamente (tabelle perfette, nessun garble)
  // false = estrazione testo pdfjs (comportamento v1)
  useV2Extraction: true,

  // ── DOCUMENTO PDF ─────────────────────────────────────────────────────────
  pdfFooter: "Progettiamo la tua protezione · polobassano.it",
  pdfBrand:  "Polo Assicurativo Bassano",
};
