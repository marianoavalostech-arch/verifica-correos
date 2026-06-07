/**
 * Verifica Correos — Función serverless para Netlify
 *
 * Fuentes de verificación (consultadas en paralelo):
 *   1. URLhaus / abuse.ch        — libre, sin clave de API
 *   2. Google Safe Browsing v4   — requiere GOOGLE_SAFE_BROWSING_KEY
 *   3. VirusTotal v3             — requiere VIRUSTOTAL_API_KEY (opcional)
 *
 * Recibe { url } o { urls: [...] }
 * Devuelve { verdict, results, source, note }
 *
 * Endpoint: /.netlify/functions/check  →  alias /check (netlify.toml)
 */

const GSB_ENDPOINT    = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
const URLHAUS_URL     = "https://urlhaus-api.abuse.ch/v1/url/";
const VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3/urls";

const GSB_THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING",          // cubre phishing
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
];

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "https://verifica-correos.netlify.app",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

// ─────────────────────────────────────────────────────────────────
// Funciones de consulta por fuente
// ─────────────────────────────────────────────────────────────────

/**
 * Google Safe Browsing v4 — consulta en lote
 * Devuelve el array "matches" crudo de la API.
 */
async function queryGSB(urls, apiKey) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), 10_000);
  try {
    const resp = await fetch(`${GSB_ENDPOINT}?key=${apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: ctrl.signal,
      body: JSON.stringify({
        client: { clientId: "verifica-correos", clientVersion: "1.1.0" },
        threatInfo: {
          threatTypes:      GSB_THREAT_TYPES,
          platformTypes:    ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries:    urls.map((u) => ({ url: u })),
        },
      }),
    });
    if (!resp.ok) {
      console.error("GSB error:", resp.status, await resp.text());
      return [];
    }
    const data = await resp.json();
    return data.matches || [];
  } catch (err) {
    console.error("GSB exception:", err.message);
    return [];
  } finally {
    clearTimeout(tid);
  }
}

/**
 * URLhaus (abuse.ch) — base de datos abierta de URLs maliciosas.
 * Libre, sin clave. Devuelve un array de etiquetas de amenaza.
 */
async function queryUrlhaus(url) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), 8_000);
  try {
    const resp = await fetch(URLHAUS_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body:    new URLSearchParams({ url }),
      signal:  ctrl.signal,
    });
    if (!resp.ok) return [];
    const data = await resp.json();

    // "no_results" = URL desconocida; cualquier otro valor = está en la BD
    if ((data.query_status ?? "no_results") === "no_results") return [];

    const raw = (data.threat || "malware").toLowerCase();
    const map = {
      malware_download: "URLHAUS_MALWARE",
      botnet_cc:        "URLHAUS_BOTNET",
      phishing:         "URLHAUS_PHISHING",
    };
    return [map[raw] ?? "URLHAUS_MALWARE"];
  } catch {
    return [];
  } finally {
    clearTimeout(tid);
  }
}

/**
 * VirusTotal v3 — más de 90 motores antivirus.
 * Requiere apiKey; devuelve [] si la clave no está configurada o
 * si la URL aún no fue analizada.
 */
async function queryVirusTotal(url, apiKey) {
  if (!apiKey) return [];

  // El ID de una URL en VT es su base64url sin padding
  const urlId = Buffer.from(url).toString("base64url").replace(/=+$/, "");
  const ctrl  = new AbortController();
  const tid   = setTimeout(() => ctrl.abort(), 12_000);
  try {
    const resp = await fetch(`${VIRUSTOTAL_BASE}/${urlId}`, {
      headers: { "x-apikey": apiKey },
      signal:  ctrl.signal,
    });
    if (resp.status === 404) return [];   // URL no analizada aún → no es señal
    if (!resp.ok) return [];
    const data  = await resp.json();
    const stats = data?.data?.attributes?.last_analysis_stats ?? {};
    // Umbral conservador: ≥2 motores "malicious" o ≥3 "suspicious"
    if ((stats.malicious  ?? 0) >= 2) return ["VIRUSTOTAL_MALICIOSO"];
    if ((stats.suspicious ?? 0) >= 3) return ["VIRUSTOTAL_SOSPECHOSO"];
    return [];
  } catch {
    return [];
  } finally {
    clearTimeout(tid);
  }
}

// ─────────────────────────────────────────────────────────────────
// Handler principal
// ─────────────────────────────────────────────────────────────────

exports.handler = async function (event) {
  // Preflight CORS
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: CORS_HEADERS };
  }
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Method not allowed" }),
    };
  }

  // Parsear cuerpo JSON
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return {
      statusCode: 400,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
      body: JSON.stringify({ error: "JSON inválido" }),
    };
  }

  // Aceptar { url } (singular) o { urls: [...] }
  const urls = Array.isArray(body.urls)
    ? body.urls.filter(Boolean)
    : body.url
    ? [body.url]
    : [];

  if (urls.length === 0) {
    return {
      statusCode: 400,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Se requiere el campo url o urls" }),
    };
  }

  // Limitar a 500 URLs por llamada (límite de la API de Google)
  const batch     = urls.slice(0, 500);
  const truncated = urls.length > 500;

  // Credenciales (variables de entorno en Netlify)
  const GSB_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY || "";
  const VT_KEY  = process.env.VIRUSTOTAL_API_KEY       || "";

  // Fuentes activas para la nota al pie
  const activeSources = ["URLhaus"];
  if (GSB_KEY) activeSources.unshift("Google Safe Browsing");
  if (VT_KEY)  activeSources.push("VirusTotal");

  // ── Consultar todas las fuentes en paralelo ──────────────────
  const [gsbMatches, urlhausAll, vtAll] = await Promise.all([
    GSB_KEY
      ? queryGSB(batch, GSB_KEY)
      : Promise.resolve([]),
    Promise.all(batch.map((u) => queryUrlhaus(u))),
    Promise.all(batch.map((u) => queryVirusTotal(u, VT_KEY))),
  ]);

  // ── Combinar resultados por URL ───────────────────────────────
  const results = batch.map((url, i) => {
    const gsbThreats = gsbMatches
      .filter((m) => m.threat?.url === url)
      .map((m) => m.threatType);

    const threats = [
      ...gsbThreats,
      ...(urlhausAll[i] || []),
      ...(vtAll[i]      || []),
    ];

    return {
      url,
      verdict: threats.length ? "dangerous" : "safe",
      threats,
    };
  });

  const anyDangerous = results.some((r) => r.verdict === "dangerous");
  const sourceStr    = activeSources.join(" + ");

  let note =
    `Resultado orientativo. Fuentes consultadas: ${sourceStr}. ` +
    "Ninguna herramienta detecta el 100 % de las amenazas: " +
    "un correo puede ser peligroso aunque aparezca como limpio.";
  if (truncated) {
    note += ` Solo se verificaron las primeras 500 de ${urls.length} URLs.`;
  }
  if (!GSB_KEY && !VT_KEY) {
    note +=
      " Para mayor cobertura, configura GOOGLE_SAFE_BROWSING_KEY y/o VIRUSTOTAL_API_KEY.";
  }

  return respond({
    verdict: anyDangerous ? "dangerous" : "safe",
    results,
    source: sourceStr,
    note,
  });
};

// ─────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────
function respond(body) {
  return {
    statusCode: 200,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}
