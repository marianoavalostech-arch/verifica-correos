/**
 * Verifica Correos — Función serverless para Netlify
 *
 * Recibe { url } o { urls: [...] } y consulta Google Safe Browsing v4.
 * La API key vive en una variable de entorno de Netlify, nunca en el código.
 *
 * Endpoint en producción: /.netlify/functions/check
 * Alias vía netlify.toml:  /check
 */

const GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

const THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING",        // incluye phishing
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
];

const NOTE =
  "Resultado orientativo. Ninguna herramienta detecta el 100 % de las amenazas: " +
  "un correo puede ser peligroso aunque aparezca como limpio. " +
  "Datos de Google Safe Browsing (uso no comercial).";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "https://verifica-correos.netlify.app",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

// ---------------------------------------------------------------------------
// Handler principal
// ---------------------------------------------------------------------------

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

  const API_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

  // Sin API key: respuesta degradada pero sin error visible al usuario
  if (!API_KEY) {
    return respond({
      verdict: "unknown",
      results: [],
      source: "none",
      note: "El servidor no tiene configurada la API key de Google Safe Browsing. Contacta al administrador.",
    });
  }

  // Parsear body
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

  // Aceptar url (singular) o urls (array)
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
  const batch = urls.slice(0, 500);
  const truncated = urls.length > 500;

  // ---------------------------------------------------------------------------
  // Consulta a Google Safe Browsing (con timeout de 10 s)
  // ---------------------------------------------------------------------------
  let matches = [];
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10_000);

    let gsb;
    try {
      gsb = await fetch(`${GSB_ENDPOINT}?key=${API_KEY}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
        body: JSON.stringify({
          client: { clientId: "verifica-correos", clientVersion: "1.0.0" },
          threatInfo: {
            threatTypes: THREAT_TYPES,
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: batch.map((u) => ({ url: u })),
          },
        }),
      });
    } finally {
      clearTimeout(timeoutId);
    }

    if (!gsb.ok) {
      const errText = await gsb.text();
      throw new Error(`GSB ${gsb.status}: ${errText}`);
    }

    const data = await gsb.json();
    matches = data.matches || [];
  } catch (err) {
    console.error("Error consultando Safe Browsing:", err.message);
    return respond({
      verdict: "unknown",
      results: batch.map((url) => ({ url, verdict: "unknown", threats: [] })),
      source: "google_safe_browsing",
      note: `No se pudo completar la consulta a Google Safe Browsing. (${err.message})`,
    });
  }

  // ---------------------------------------------------------------------------
  // Construir resultados por URL
  // ---------------------------------------------------------------------------
  const results = batch.map((url) => {
    const urlMatches = matches.filter(
      (m) => m.threat && m.threat.url === url
    );
    const threats = urlMatches.map((m) => m.threatType);
    return { url, verdict: threats.length ? "dangerous" : "safe", threats };
  });

  const anyDangerous = results.some((r) => r.verdict === "dangerous");

  const note = truncated
    ? `${NOTE} Solo se verificaron las primeras 500 de ${urls.length} URLs enviadas.`
    : NOTE;

  return respond({
    verdict: anyDangerous ? "dangerous" : "safe",
    results,
    source: "google_safe_browsing",
    note,
  });
};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------
function respond(body) {
  return {
    statusCode: 200,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}
