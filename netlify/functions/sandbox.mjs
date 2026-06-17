/**
 * Verifica Correos — Captura en sandbox remoto (urlscan.io)
 * Netlify Functions v2 (ESM)
 *
 * Objetivo: generar una imagen del destino FINAL de un enlace (siguiendo sus
 * redirects) SIN que el usuario abra el enlace en su equipo. El renderizado lo
 * hace urlscan.io en un entorno aislado; el navegador del usuario nunca contacta
 * al sitio sospechoso ni a urlscan: solo habla con esta función.
 *
 * Privacidad: los escaneos se envían con visibility "unlisted" para que NO
 * aparezcan en el buscador público de urlscan.
 *
 * CSP: la captura se devuelve como data URL base64 (no una URL externa), de modo
 * que `img-src 'self' data:` la permite sin aflojar la política de seguridad.
 *
 * Acciones (POST JSON):
 *   { action: "submit", url }   → { uuid, reportUrl }
 *   { action: "result", uuid }  → { status: "pending" }
 *                               | { status: "done", finalUrl, malicious, score,
 *                                   screenshot (data URL|null), reportUrl }
 *
 * Requiere URLSCAN_API_KEY (gratuita en https://urlscan.io/user/signup/).
 *
 * Endpoint: /sandbox (definido en config.path). Rate limit propio (Functions v2).
 */

const URLSCAN_SUBMIT = "https://urlscan.io/api/v1/scan/";
const urlscanResult  = (uuid) => `https://urlscan.io/api/v1/result/${uuid}/`;

// urlscan devuelve UUID v4; se valida con un patrón estricto para evitar que un
// valor arbitrario se inyecte en la ruta del fetch (anti-SSRF/path traversal).
const UUID_RE      = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VALID_URL_RE = /^https?:\/\/.{3,2048}$/;
const MAX_BODY_SIZE = 8_000;
const MAX_SCREENSHOT_BYTES = 4_000_000; // ~4 MB; evita respuestas gigantes

// SEGURIDAD: igual que /check, restringir CORS al origen propio en producción.
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

async function fetchWithTimeout(url, opts = {}, ms = 8000) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(tid);
  }
}

// Rechaza hosts internos/privados para no pedirle a urlscan que escanee la red
// interna ni direcciones de loopback.
function isPublicHttpUrl(url) {
  let u;
  try { u = new URL(url); } catch { return false; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    host === "localhost" || host.endsWith(".localhost") ||
    host.endsWith(".local") || host.endsWith(".internal") ||
    (!host.includes(".") && !host.includes(":"))
  ) return false;
  // IPv4 literal privada / loopback / link-local
  const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
        (a === 100 && b >= 64 && b <= 127) || a >= 224) return false;
  }
  if (host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80")) return false;
  return true;
}

export default async function handler(req) {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }
  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }
  if (process.env.ALLOWED_ORIGIN) {
    const origin = req.headers.get("origin") || "";
    if (origin !== process.env.ALLOWED_ORIGIN) {
      return json({ error: "Origen no permitido" }, 403);
    }
  }

  const apiKey = process.env.URLSCAN_API_KEY || "";
  if (!apiKey) {
    return json({
      error: "Sandbox no disponible: falta URLSCAN_API_KEY en el servidor. " +
             "Obtené una clave gratuita en urlscan.io y configurala en las variables de entorno.",
    }, 503);
  }

  const rawBody = await req.text();
  if (rawBody.length > MAX_BODY_SIZE) return json({ error: "Payload demasiado grande" }, 413);
  let body;
  try { body = JSON.parse(rawBody || "{}"); } catch { return json({ error: "JSON inválido" }, 400); }

  // ── Enviar URL a escanear ──────────────────────────────────────────────
  if (body.action === "submit") {
    const url = body.url;
    if (typeof url !== "string" || !VALID_URL_RE.test(url) || !isPublicHttpUrl(url)) {
      return json({ error: "URL inválida o no pública (http/https)." }, 400);
    }
    let resp, data;
    try {
      resp = await fetchWithTimeout(URLSCAN_SUBMIT, {
        method: "POST",
        headers: { "Content-Type": "application/json", "API-Key": apiKey },
        body: JSON.stringify({ url, visibility: "unlisted" }),
      }, 8000);
      data = await resp.json().catch(() => null);
    } catch {
      return json({ error: "No se pudo contactar con urlscan.io." }, 502);
    }
    if (resp.status === 429) {
      return json({ error: "Límite de urlscan alcanzado. Esperá un momento e intentá de nuevo." }, 429);
    }
    if (!resp.ok || !data?.uuid) {
      return json({ error: data?.description || data?.message || `urlscan rechazó el envío (HTTP ${resp.status}).` }, 502);
    }
    return json({ uuid: data.uuid, reportUrl: data.result || null });
  }

  // ── Consultar resultado ────────────────────────────────────────────────
  if (body.action === "result") {
    const uuid = body.uuid;
    if (typeof uuid !== "string" || !UUID_RE.test(uuid)) {
      return json({ error: "uuid inválido" }, 400);
    }
    let resp;
    try {
      resp = await fetchWithTimeout(urlscanResult(uuid), { headers: { "API-Key": apiKey } }, 6000);
    } catch {
      return json({ error: "No se pudo consultar urlscan.io." }, 502);
    }
    // 404 = el escaneo aún se está procesando.
    if (resp.status === 404) return json({ status: "pending" });
    if (!resp.ok) return json({ error: `urlscan error (HTTP ${resp.status}).` }, 502);

    const data = await resp.json().catch(() => null);
    if (!data) return json({ error: "Respuesta de urlscan ilegible." }, 502);

    const finalUrl  = data?.page?.url || null;
    const malicious = !!data?.verdicts?.overall?.malicious;
    const score     = Number(data?.verdicts?.overall?.score ?? 0);
    const reportUrl = data?.task?.reportURL || null;
    const shotUrl   = data?.task?.screenshotURL || null;

    // Descargar la captura en el servidor y devolverla como data URL base64.
    let screenshot = null;
    if (shotUrl) {
      try {
        const s = await fetchWithTimeout(shotUrl, { headers: { "API-Key": apiKey } }, 6000);
        if (s.ok) {
          const buf = Buffer.from(await s.arrayBuffer());
          if (buf.length > 0 && buf.length <= MAX_SCREENSHOT_BYTES) {
            screenshot = "data:image/png;base64," + buf.toString("base64");
          }
        }
      } catch { /* sin captura → screenshot queda null */ }
    }

    return json({ status: "done", finalUrl, malicious, score, screenshot, reportUrl });
  }

  return json({ error: "action debe ser 'submit' o 'result'." }, 400);
}

export const config = {
  path: "/sandbox",
  // Más estricto que /check: cada escaneo consume cuota de urlscan.
  rateLimit: {
    windowLimit: 10,
    windowSize: 60,
    aggregateBy: ["ip", "domain"],
  },
};
