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
 * Endpoint: /.netlify/functions/check  ->  alias /check (netlify.toml)
 */

const GSB_ENDPOINT    = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
const URLHAUS_URL     = "https://urlhaus-api.abuse.ch/v1/url/";
const VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3/urls";

const GSB_THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
];

// SEGURIDAD: ALLOWED_ORIGIN debe configurarse en producción.
// Sin ella, cualquier sitio puede llamar a este endpoint y abusar de las API keys.
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

// Solo se aceptan URLs con protocolo http(s) y longitud razonable.
const VALID_URL_RE = /^https?:\/\/.{3,2000}$/;

// Límite de URLs por llamada y tamaño máximo del body (bytes).
const MAX_URLS      = 100;
const MAX_BODY_SIZE = 50_000;

// --- Funciones de consulta por fuente ---

async function queryGSB(urls, apiKey) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), 10000);
  try {
    // SEGURIDAD: la clave viaja en el header, no en la URL (evita exposición en logs).
    const resp = await fetch(GSB_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
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
      console.error("GSB error:", resp.status); // No loggar el body: puede contener detalles de la clave
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
 * CORRECCIÓN: verificar query_status === "is_listed" en vez de !== "no_results"
 * para evitar falsos positivos con estados "not_listed" y "404".
 */
async function queryUrlhaus(url) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), 8000);
  try {
    const resp = await fetch(URLHAUS_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body:    new URLSearchParams({ url }),
      signal:  ctrl.signal,
    });
    if (!resp.ok) return [];
    const data = await resp.json();

    // Solo "is_listed" confirma que la URL esta en la base de datos.
    // Otros estados posibles: "no_results", "not_listed", "404" -> URL limpia.
    if ((data.query_status ?? "no_results") !== "is_listed") return [];

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
 * VirusTotal v3 — mas de 90 motores antivirus.
 * CORRECCIÓN: .toString("base64url") ya omite padding; el .replace() era redundante.
 */
async function queryVirusTotal(url, apiKey) {
  if (!apiKey) return [];

  const urlId = Buffer.from(url).toString("base64url");
  const ctrl  = new AbortController();
  const tid   = setTimeout(() => ctrl.abort(), 12000);
  try {
    const resp = await fetch(`${VIRUSTOTAL_BASE}/${urlId}`, {
      headers: { "x-apikey": apiKey },
      signal:  ctrl.signal,
    });
    if (resp.status === 404) return [];
    if (!resp.ok) return [];
    const data  = await resp.json();
    const stats = data?.data?.attributes?.last_analysis_stats ?? {};
    if ((stats.malicious  ?? 0) >= 2) return ["VIRUSTOTAL_MALICIOSO"];
    if ((stats.suspicious ?? 0) >= 3) return ["VIRUSTOTAL_SOSPECHOSO"];
    return [];
  } catch {
    return [];
  } finally {
    clearTimeout(tid);
  }
}

// --- Handler principal ---

exports.handler = async function (event) {
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

  // SEGURIDAD: rechazar payloads excesivamente grandes antes de parsear.
  if ((event.body || "").length > MAX_BODY_SIZE) {
    return {
      statusCode: 413,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Payload demasiado grande" }),
    };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return {
      statusCode: 400,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
      body: JSON.stringify({ error: "JSON invalido" }),
    };
  }

  const rawUrls = Array.isArray(body.urls)
    ? body.urls.filter(Boolean)
    : body.url
    ? [body.url]
    : [];

  // SEGURIDAD: filtrar solo URLs con protocolo http/https y longitud razonable.
  const urls = rawUrls.filter(
    (u) => typeof u === "string" && VALID_URL_RE.test(u)
  );

  if (urls.length === 0) {
    return {
      statusCode: 400,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Se requiere el campo url o urls (con protocolo http/https)" }),
    };
  }

  const batch     = urls.slice(0, MAX_URLS);
  const truncated = urls.length > MAX_URLS;

  // useVT: el cliente puede deshabilitar VirusTotal aunque la clave esté configurada.
  // Por defecto true para mantener compatibilidad con llamadas sin el campo.
  const useVT = body.useVT !== false;

  const GSB_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY || "";
  const VT_KEY  = (useVT && process.env.VIRUSTOTAL_API_KEY) || "";

  const activeSources = ["URLhaus"];
  if (GSB_KEY) activeSources.unshift("Google Safe Browsing");
  if (VT_KEY)  activeSources.push("VirusTotal");

  const [gsbMatches, urlhausAll, vtAll] = await Promise.all([
    GSB_KEY
      ? queryGSB(batch, GSB_KEY)
      : Promise.resolve([]),
    Promise.all(batch.map((u) => queryUrlhaus(u))),
    Promise.all(batch.map((u) => queryVirusTotal(u, VT_KEY))),
  ]);

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
    "Resultado orientativo. Fuentes consultadas: " + sourceStr + ". " +
    "Ninguna herramienta detecta el 100 % de las amenazas: " +
    "un correo puede ser peligroso aunque aparezca como limpio.";
  if (truncated) {
    note += " Solo se verificaron las primeras " + MAX_URLS + " de " + urls.length + " URLs.";
  }
  if (!GSB_KEY && !VT_KEY) {
    note += " Para mayor cobertura, configura GOOGLE_SAFE_BROWSING_KEY y/o VIRUSTOTAL_API_KEY.";
  }

  return respond({
    verdict: anyDangerous ? "dangerous" : "safe",
    results,
    source: sourceStr,
    note,
  });
};

// --- Rate limiting (plan gratuito: hasta 2 reglas por proyecto) ---
// 20 requests/min por IP ≈ protege la cuota diaria de Google Safe Browsing (~10 000 req/día).
exports.config = {
  path: "/check",
  rateLimit: {
    windowLimit: 20,
    windowSize: 60,
    aggregateBy: ["ip", "domain"],
  },
};

// --- Helper ---
function respond(body) {
  return {
    statusCode: 200,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}
