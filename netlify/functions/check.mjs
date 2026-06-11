/**
 * Verifica Correos — Función serverless para Netlify (Functions v2, ESM)
 *
 * Fuentes de verificación (consultadas en paralelo):
 *   1. URLhaus / abuse.ch        — requiere ABUSECH_AUTH_KEY (gratuita, auth.abuse.ch)
 *   2. ThreatFox / abuse.ch      — requiere ABUSECH_AUTH_KEY (misma clave)
 *   3. Google Safe Browsing v4   — requiere GOOGLE_SAFE_BROWSING_KEY
 *   4. VirusTotal v3             — requiere VIRUSTOTAL_API_KEY (opcional)
 *
 * Nota: desde 2025 abuse.ch exige autenticación con Auth-Key en sus APIs.
 * Sin la clave, las consultas a URLhaus/ThreatFox se omiten.
 *
 * Recibe { url } o { urls: [...] }
 * Devuelve { verdict, results, source, note }
 *
 * Endpoint: /check (definido en `config.path`, sin redirect en netlify.toml).
 *
 * MIGRACIÓN A V2: la sintaxis v1 (exports.handler) ignoraba `exports.config`,
 * por lo que el rate limiting nunca se aplicaba. Con v2 (export default +
 * export const config) Netlify sí registra la regla de rate limit.
 */

import { promises as dns } from "node:dns";

const GSB_ENDPOINT    = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
const URLHAUS_URL     = "https://urlhaus-api.abuse.ch/v1/url/";
const THREATFOX_URL   = "https://threatfox-api.abuse.ch/api/v1/";
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
if (!process.env.ALLOWED_ORIGIN) {
  console.warn(
    "[seguridad] ALLOWED_ORIGIN no está configurada: el endpoint /check " +
    "acepta peticiones CORS desde CUALQUIER origen. Configúrala en " +
    "Site settings → Environment variables antes de usar en producción."
  );
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

// Solo se aceptan URLs con protocolo http(s) y longitud razonable.
const VALID_URL_RE = /^https?:\/\/.{3,2000}$/;

// --- Protección SSRF -------------------------------------------------------
// followRedirects() hace fetch desde el servidor a URLs controladas por el
// usuario. Sin este filtro, una URL como http://169.254.169.254/ o
// http://localhost:8080/ haría que la función consulte servicios internos.

function isPrivateIp(ip) {
  // IPv4
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||   // CGNAT 100.64/10
      (a === 169 && b === 254) ||             // link-local / metadata
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a >= 224                                 // multicast / reservado
    );
  }
  // IPv6 (forma normalizada de Node)
  const v6 = ip.toLowerCase();
  return (
    v6 === "::1" || v6 === "::" ||
    v6.startsWith("fe80") ||                  // link-local
    v6.startsWith("fc") || v6.startsWith("fd") || // ULA fc00::/7
    v6.startsWith("::ffff:127.") || v6.startsWith("::ffff:10.") ||
    v6.startsWith("::ffff:192.168.") || v6.startsWith("::ffff:169.254.")
  );
}

/**
 * true si la URL apunta a un host público al que es seguro hacer fetch.
 * Rechaza hostnames internos, IPs literales privadas y nombres que
 * resuelven a IPs privadas.
 */
async function isSafePublicUrl(url) {
  let host;
  try {
    host = new URL(url).hostname.replace(/^\[|\]$/g, "");
  } catch { return false; }

  const lower = host.toLowerCase();
  if (
    lower === "localhost" ||
    lower.endsWith(".localhost") ||
    lower.endsWith(".local") ||
    lower.endsWith(".internal") ||
    !lower.includes(".") && !lower.includes(":")  // nombres sin punto (hosts internos)
  ) return false;

  if (isPrivateIp(lower)) return false;          // IP literal

  // Resolver el hostname y verificar todas las IPs devueltas
  try {
    const addrs = await dns.lookup(lower, { all: true, verbatim: true });
    if (addrs.length === 0) return false;
    return addrs.every((a) => !isPrivateIp(a.address));
  } catch {
    return false; // no resuelve → no se hace fetch
  }
}

// Límite de URLs por llamada y tamaño máximo del body (bytes).
const MAX_URLS           = 100;
const MAX_BODY_SIZE      = 50_000;
// Cap de seguridad: evita que redirect expansion genere cientos de requests a abuse.ch.
// En el peor caso teórico: 100 URLs × 3 saltos = 300; el cap lo acota a este valor.
const MAX_ALLCHECK_URLS  = 300;

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
        client: { clientId: "verifica-correos", clientVersion: "1.4.0" },
        threatInfo: {
          threatTypes:      GSB_THREAT_TYPES,
          platformTypes:    ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries:    urls.map((u) => ({ url: u })),
        },
      }),
    });
    if (!resp.ok) {
      console.error("GSB error:", resp.status);
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
 * Verificar query_status === "is_listed" para evitar falsos positivos.
 */
async function queryUrlhaus(url, authKey) {
  if (!authKey) return [];
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), 8000);
  try {
    const resp = await fetch(URLHAUS_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Auth-Key":     authKey,
      },
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
 * ThreatFox (abuse.ch) — base de datos de IOCs (dominios e IPs maliciosas).
 * Consulta por hostname extraído de la URL.
 * Cubre infraestructura de C2, distribución de malware y phishing.
 */
async function queryThreatFox(url, authKey) {
  if (!authKey) return [];
  let hostname;
  try {
    hostname = new URL(url).hostname;
  } catch {
    return [];
  }

  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), 8000);
  try {
    const resp = await fetch(THREATFOX_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json", "Auth-Key": authKey },
      body:    JSON.stringify({ query: "search_ioc", search_term: hostname }),
      signal:  ctrl.signal,
    });
    if (!resp.ok) return [];
    const data = await resp.json();

    // "no_results" significa dominio limpio en la base de datos.
    if ((data.query_status ?? "no_results") !== "ok") return [];
    if (!Array.isArray(data.data) || data.data.length === 0) return [];

    const map = {
      botnet_cc:        "THREATFOX_BOTNET",
      payload_delivery: "THREATFOX_MALWARE",
      phishing:         "THREATFOX_PHISHING",
    };
    const threatType = data.data[0]?.threat_type ?? "";
    return [map[threatType] ?? "THREATFOX_MALWARE"];
  } catch {
    return [];
  } finally {
    clearTimeout(tid);
  }
}

/**
 * VirusTotal v3 — mas de 90 motores antivirus.
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

/**
 * Sigue redirects HTTP para una URL (máx. maxHops saltos).
 * Intenta HEAD primero (sin body); si el servidor bloquea HEAD (405/400/error)
 * o devuelve 2xx sin redirigir, reintenta con GET + redirect:"manual".
 * Con redirect:"manual" el body nunca se descarga para respuestas 3xx.
 * Devuelve la cadena completa: [urlOriginal, salto1, salto2, ...].
 */
async function followRedirects(startUrl, maxHops = 3) {
  const BROWSER_UA =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

  const chain   = [startUrl];
  let current   = startUrl;

  // SEGURIDAD: nunca hacer fetch a hosts internos o IPs privadas (SSRF).
  if (!(await isSafePublicUrl(startUrl))) return chain;

  for (let i = 0; i < maxHops; i++) {
    let location = null;

    // Intenta HEAD; si falla o responde 405/400 sin redirect, prueba GET.
    for (const method of ["HEAD", "GET"]) {
      const ctrl = new AbortController();
      const tid  = setTimeout(() => ctrl.abort(), 5000);
      let resp;
      try {
        resp = await fetch(current, {
          method,
          redirect: "manual",
          signal:   ctrl.signal,
          headers:  { "User-Agent": BROWSER_UA },
        });
      } catch {
        clearTimeout(tid);
        break;
      }
      clearTimeout(tid);

      if (resp.status >= 300 && resp.status < 400) {
        location = resp.headers.get("location");
        break;                          // redirect encontrado
      }
      // HEAD rechazado → probar GET
      if (method === "HEAD" && (resp.status === 405 || resp.status === 400)) {
        continue;
      }
      break;                            // 2xx u otro código → no hay redirect
    }

    if (!location) break;
    let next;
    try { next = new URL(location, current).href; } catch { break; }
    if (chain.includes(next)) break;     // evitar ciclos
    if (!VALID_URL_RE.test(next)) break; // solo http/https
    // SEGURIDAD: el salto se registra en la cadena (para mostrarlo y verificarlo
    // contra las APIs), pero si apunta a un host privado no se sigue (SSRF).
    chain.push(next);
    if (!(await isSafePublicUrl(next))) break;
    current = next;
  }
  return chain;
}

// --- Helper de respuesta JSON (API Response de Functions v2) ---

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

// --- Handler principal (Netlify Functions v2) ---

export default async function handler(req) {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }
  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  // SEGURIDAD: rechazar payloads excesivamente grandes antes de parsear.
  const rawBody = await req.text();
  if (rawBody.length > MAX_BODY_SIZE) {
    return json({ error: "Payload demasiado grande" }, 413);
  }

  let body;
  try {
    body = JSON.parse(rawBody || "{}");
  } catch {
    return json({ error: "JSON invalido" }, 400);
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
    return json(
      { error: "Se requiere el campo url o urls (con protocolo http/https)" },
      400
    );
  }

  const batch     = urls.slice(0, MAX_URLS);
  const truncated = urls.length > MAX_URLS;

  // useVT: el cliente puede deshabilitar VirusTotal aunque la clave esté configurada.
  // Por defecto true para mantener compatibilidad con llamadas sin el campo.
  const useVT = body.useVT !== false;

  const GSB_KEY     = process.env.GOOGLE_SAFE_BROWSING_KEY || "";
  const ABUSECH_KEY = process.env.ABUSECH_AUTH_KEY || "";
  const VT_KEY      = (useVT && process.env.VIRUSTOTAL_API_KEY) || "";

  const activeSources = [];
  if (GSB_KEY)     activeSources.push("Google Safe Browsing");
  if (ABUSECH_KEY) activeSources.push("URLhaus", "ThreatFox");
  if (VT_KEY)      activeSources.push("VirusTotal");

  // Seguir redirects HTTP para detectar cadenas multi-salto
  // (ej: redirector corporativo → landing → página de phishing real).
  const redirectChainMap = new Map(); // url original → [url, salto1, salto2, ...]
  await Promise.all(
    batch.map(async (url) => {
      redirectChainMap.set(url, await followRedirects(url));
    })
  );

  // URLs únicas a verificar: originales + todos los saltos descubiertos.
  // Se aplica MAX_ALLCHECK_URLS para acotar el número de requests a las APIs externas.
  const allCheckUrls = [...new Set(
    batch.concat([...redirectChainMap.values()].flat())
  )].slice(0, MAX_ALLCHECK_URLS);

  const [gsbMatches, urlhausAll, threatfoxAll, vtAll] = await Promise.all([
    GSB_KEY
      ? queryGSB(allCheckUrls, GSB_KEY)
      : Promise.resolve([]),
    Promise.all(allCheckUrls.map((u) => queryUrlhaus(u, ABUSECH_KEY))),
    Promise.all(allCheckUrls.map((u) => queryThreatFox(u, ABUSECH_KEY))),
    Promise.all(allCheckUrls.map((u) => queryVirusTotal(u, VT_KEY))),
  ]);

  // Mapa url → threats[] para búsqueda rápida en toda la cadena
  const threatsByUrl = new Map();
  for (let i = 0; i < allCheckUrls.length; i++) {
    const u = allCheckUrls[i];
    const gsbThreats = gsbMatches
      .filter((m) => m.threat?.url === u)
      .map((m) => m.threatType);
    const threats = [
      ...gsbThreats,
      ...(urlhausAll[i] || []),
      ...(threatfoxAll[i] || []),
      ...(vtAll[i] || []),
    ];
    if (threats.length) threatsByUrl.set(u, threats);
  }

  const results = batch.map((url) => {
    const chain   = redirectChainMap.get(url) || [url];
    const threats = [...new Set(chain.flatMap(u => threatsByUrl.get(u) || []))];
    const redirectHops = chain.slice(1);
    return {
      url,
      verdict: threats.length ? "dangerous" : "safe",
      threats,
      ...(redirectHops.length > 0 && { redirectChain: redirectHops }),
    };
  });

  const anyDangerous = results.some((r) => r.verdict === "dangerous");
  const sourceStr    = activeSources.length
    ? activeSources.join(" + ")
    : "ninguna (sin claves de API configuradas)";

  let note =
    "Resultado orientativo. Fuentes consultadas: " + sourceStr + ". " +
    "Se analizan también los destinos de redirects HTTP (hasta 3 saltos). " +
    "Ninguna herramienta detecta el 100 % de las amenazas: " +
    "un correo puede ser peligroso aunque aparezca como limpio.";
  if (truncated) {
    note += " Solo se verificaron las primeras " + MAX_URLS + " de " + urls.length + " URLs.";
  }
  if (!GSB_KEY || !ABUSECH_KEY) {
    note += " Para mayor cobertura, configura GOOGLE_SAFE_BROWSING_KEY y ABUSECH_AUTH_KEY (ambas gratuitas).";
  }

  return json({
    verdict: anyDangerous ? "dangerous" : "safe",
    results,
    source: sourceStr,
    note,
  });
}

// --- Configuración: ruta + rate limiting ------------------------------------
// Con Functions v2 esta configuración SÍ se registra (en v1 se ignoraba).
// 20 requests/min por IP ≈ protege la cuota diaria de Google Safe Browsing (~10 000 req/día).
export const config = {
  path: "/check",
  rateLimit: {
    windowLimit: 20,
    windowSize: 60,
    aggregateBy: ["ip", "domain"],
  },
};
