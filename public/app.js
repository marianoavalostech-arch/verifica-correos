// ═══════════════════════════════════════════════════════
//  Constantes
// ═══════════════════════════════════════════════════════

const CHECK_ENDPOINT = "/check";

const STD_NOTE =
  "Resultado orientativo. Ninguna herramienta detecta el 100 % de las amenazas. " +
  "Un correo puede ser peligroso aunque aparezca como limpio. " +
  "Fuentes del servidor (según claves configuradas): Google Safe Browsing, URLhaus y ThreatFox (abuse.ch), VirusTotal. " +
  "Se analizan cadenas de redirects HTTP de hasta 3 saltos. " +
  "Fuentes del navegador: Cloudflare DNS (MX/SPF/DMARC), RDAP (antigüedad), análisis heurístico propio.";

const COMMON_DOMAINS = [
  "gmail.com","googlemail.com","hotmail.com","hotmail.es","hotmail.com.ar",
  "outlook.com","outlook.es","yahoo.com","yahoo.es","yahoo.com.ar",
  "icloud.com","me.com","live.com","live.com.ar","msn.com",
  "protonmail.com","proton.me","tutanota.com","tutanota.de",
];

const SUSPICIOUS_TLDS = new Set([
  // Freenom gratuitos (muy abusados para phishing)
  "tk","ml","ga","cf","gq",
  // Genéricos baratos y abusados
  "xyz","top","click","work","loan","stream","gdn","racing",
  "trade","review","science","date","faith","bid","win","party",
  "download","accountant",
  // Nuevos gTLDs con alto índice de abuso
  "zip","mov","cam","icu","vip","buzz","cyou","cfd","sbs",
  "hair","uno","monster","rest","pw","cc","su","ws",
  // gTLDs genéricos con alta tasa de phishing
  "online","site","live","store","club",
]);

const URL_SHORTENERS = new Set([
  "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","short.link",
  "cutt.ly","rb.gy","is.gd","v.gd","buff.ly","bl.ink","rebrand.ly",
  "link.tl","tiny.cc","clck.ru","soo.gd","shrinkme.io","shorturl.at",
  "adf.ly","bc.vc","s.id","qr.io","short.io",
  // Acortadores adicionales frecuentemente usados en phishing
  "x.co","su.pr","snip.ly","mcaf.ee","po.st","hyperurl.co",
  "lnnk.in","zpr.io","go2l.ink","tr.im","cli.gs","1url.com",
  "urlo.ws","2url.net","multiurl.com","chilp.it",
  // Acortadores genéricos .uk/.link/.to y similares (vistos en phishing real)
  "shortlink.uk","short.gy","kutt.it","t.ly","tinu.be","l.ink",
  "shorturl.gg","spoo.me","linkr.it","da.gd","gg.gg","u.to",
  "ulvis.net","clicky.me","shorten.ee","2ty.cc","tny.im",
]);

// Plataformas de email marketing que usan redirección de enlaces
// (el dominio real del destino está oculto detrás de su servidor)
const EMAIL_TRACKER_DOMAINS = {
  "customeriomail.com": "Customer.io",
  "cio-sb.com":         "Customer.io",
  "sendgrid.net":       "SendGrid",
  "sgo.to":             "SendGrid",
  "list-manage.com":    "Mailchimp",
  "mailchi.mp":         "Mailchimp",
  "hs-email.com":       "HubSpot",
  "hsmail.net":         "HubSpot",
  "mktomail.com":       "Marketo",
  "mktdns.com":         "Marketo",
  "exacttarget.com":    "Salesforce Marketing Cloud",
  "salesforceiq.com":   "Salesforce",
  "cmail20.com":        "Campaign Monitor",
  "createsend.com":     "Campaign Monitor",
  "klaviyo.com":        "Klaviyo",
  "mailerlite.com":     "MailerLite",
  "activecampaign.com": "ActiveCampaign",
  "brevo.com":          "Brevo (Sendinblue)",
  "omnisend.com":       "Omnisend",
};

const THREAT_LABELS = {
  // Google Safe Browsing
  MALWARE:                         "Malware (Google Safe Browsing)",
  SOCIAL_ENGINEERING:              "Phishing / Ingeniería social (Google)",
  UNWANTED_SOFTWARE:               "Software no deseado (Google)",
  POTENTIALLY_HARMFUL_APPLICATION: "App potencialmente dañina (Google)",
  // URLhaus / abuse.ch
  URLHAUS_MALWARE:                 "Malware (URLhaus)",
  URLHAUS_BOTNET:                  "Botnet C2 (URLhaus)",
  URLHAUS_PHISHING:                "Phishing (URLhaus)",
  // VirusTotal
  VIRUSTOTAL_MALICIOSO:            "Malicioso por múltiples motores (VirusTotal)",
  VIRUSTOTAL_SOSPECHOSO:           "Sospechoso por múltiples motores (VirusTotal)",
  // ThreatFox / abuse.ch
  THREATFOX_MALWARE:               "Distribución de malware (ThreatFox)",
  THREATFOX_BOTNET:                "Infraestructura de botnet C2 (ThreatFox)",
  THREATFOX_PHISHING:              "Phishing (ThreatFox)",
};

// Reglas heurísticas para el cuerpo del correo
const BODY_RULES = [
  {
    id: "urgencia",
    label: "Lenguaje de urgencia",
    score: 20,
    patterns: [
      /urg[ei]nte/i, /urgencia/i, /inmediata?mente/i, /de inmediato/i,
      /24 horas/i, /48 horas/i, /vence (hoy|mañana)/i, /plazo/i,
      /lo antes posible/i, /ahora mismo/i, /cuanto antes/i,
      // English
      /\burgent\b/i, /\bimmediately\b/i, /right away/i,
      /action required/i, /immediate action/i,
      /within \d+ hours?/i, /expires? (?:today|soon|tomorrow)/i,
    ],
    desc: () => "Usa lenguaje de urgencia para presionar al destinatario a actuar sin pensar.",
  },
  {
    id: "credenciales",
    label: "Solicitud de datos sensibles",
    score: 45,
    patterns: [
      /contrase[ñn]a/i, /clave de acceso/i, /\bpin\b/i,
      /n[uú]mero de tarjeta/i, /cuenta bancaria/i, /datos bancarios/i,
      /\bcvv\b/i, /datos personales/i, /informaci[oó]n personal/i,
      /datos de acceso/i, /passw/i,
    ],
    desc: () => "Solicita contraseñas, datos bancarios u otra información confidencial.",
  },
  {
    id: "amenaza",
    label: "Amenaza de suspensión o pérdida",
    score: 35,
    patterns: [
      /suspendid[ao]/i, /bloquead[ao]/i, /cancelad[ao]/i,
      /cerrad[ao]/i, /eliminad[ao]/i, /desactivad[ao]/i,
      /acceso restringido/i, /ser[aá] bloqueada/i, /ser[aá] suspendida/i,
      /perder[aá] (su |el )?acceso/i,
      // English
      /account.{0,20}(?:restricted|suspended|blocked|limited|locked)/i,
      /access.{0,20}(?:restricted|suspended|blocked|limited)/i,
      /temporarily.{0,20}(?:limited|restricted|suspended|blocked)/i,
    ],
    desc: () => "Amenaza con suspender, bloquear o cancelar tu cuenta si no actúas.",
  },
  {
    id: "premio",
    label: "Promesa de premio o recompensa",
    score: 30,
    patterns: [
      /\bgan[oó]\b/i, /\bganador\b/i, /\bpremio\b/i, /loter[ií]a/i,
      /seleccionado/i, /regalo gratis/i, /obsequio/i,
      /recompensa/i, /dinero gratis/i, /bono especial/i,
    ],
    desc: () => "Promete premios o dinero. Táctica clásica de estafas.",
  },
  {
    id: "clic",
    label: "Presión para hacer clic",
    score: 15,
    patterns: [
      /haga clic/i, /haz clic/i, /clic aqu[ií]/i, /click aqu[ií]/i,
      /pinche aqu[ií]/i, /acceda aqu[ií]/i, /confirme aqu[ií]/i,
      /verifique aqu[ií]/i, /ingrese al enlace/i, /siga el enlace/i,
      // English
      /click here/i, /click the link/i,
      /verify (?:account|your) (?:access|identity)/i,
      /takes? less than.{0,20}minutes?/i,
    ],
    desc: () => "Presiona para hacer clic en un enlace urgentemente.",
  },
  {
    id: "marca",
    label: "Posible suplantación de marca",
    score: 10,
    extractNames: true,
    patterns: [
      // Globales
      /\bpaypal\b/i, /\bnetflix\b/i, /\bamazon\b/i, /\bapple\b/i,
      /\bmicrosoft\b/i, /\bgoogle\b/i, /\bfacebook\b/i, /\binstagram\b/i,
      /\bwhatsapp\b/i, /\btelegram\b/i, /\btwitter\b/i, /\btiktok\b/i,
      /\blinkedin\b/i, /\bdropbox\b/i,
      /\bdhl\b/i, /\bfedex\b/i, /\bups\b/i,
      /\bamerican express\b/i, /\bamex\b/i,
      // Bancos / fintech
      /\bbbva\b/i, /\bsantander\b/i, /\bhsbc\b/i, /\bicbc\b/i,
      /\bcitibank\b/i, /\bnaci[oó]n\b/i, /\bgalicia\b/i,
      /\bprovincia\b/i, /\bnaranja(?:x)?\b/i, /\bbrubank\b/i, /\buala\b/i,
      // Pagos / comercio
      /\bmercadopago\b/i, /\bmercadolibre\b/i, /\bpedidosya\b/i, /\brappi\b/i,
      // Organismos / telecos
      /\bafip\b/i, /\banses\b/i, /\bpami\b/i,
      /\bmovistar\b/i, /\bclaro\b/i, /\bpersonal\b/i, /\bfibertel\b/i,
      // Correos / logística
      /\bcorreoargentino\b/i, /\bandreani\b/i,
    ],
    desc: (names) => `Menciona marcas reconocidas: ${names.join(", ")}. Verifica que el remitente use el dominio oficial.`,
  },
  // ── Reglas adicionales ──────────────────────────────────────────
  {
    id: "reembolso",
    label: "Promesa de reembolso o pago pendiente",
    score: 25,
    patterns: [
      /reembolso/i, /devoluci[oó]n de dinero/i, /te? acreditaremos/i,
      /pago pendiente/i, /tienes (?:un )?(?:pago|cobro)/i,
      /cobrar[aá]s?/i, /dinero (?:disponible|pendiente|acreditado)/i,
      /\$\s*[\d,.]+\s*(?:pesos|usd|d[oó]lares)/i,
    ],
    desc: () => "Promete reembolsos o pagos pendientes como anzuelo para que entres a un enlace.",
  },
  {
    id: "verificacion",
    label: "Solicitud de verificación de cuenta",
    score: 30,
    patterns: [
      /verifi(?:car|que|ca) (?:su|tu)/i, /confirme (?:su|tu)/i,
      /actualice? (?:sus?|tu) datos/i, /datos (?:est[aá]n )?desactualizados/i,
      /valide? (?:su|tu)/i, /por razones? de seguridad/i,
      /problema (?:con|en) (?:su|tu) cuenta/i,
      /acceso (?:inusual|sospechoso|no autorizado)/i,
      /inicio de sesi[oó]n (?:inusual|sospechoso)/i,
      // English
      /verify.{0,20}(?:your|account|identity|access)/i,
      /suspicious.{0,20}(?:sign.?in|log.?in|activity|attempt)/i,
      /unrecognized.{0,20}device/i,
      /unusual.{0,20}(?:sign.?in|activity|access)/i,
      /restore.{0,20}(?:full\s+)?access/i,
      /for your (?:protection|security)/i,
    ],
    desc: () => "Solicita verificar o actualizar datos de cuenta — táctica central de phishing.",
  },
];

// Último análisis realizado (usado para generar informes)
let lastAnalysisData = null;

// Correo de phishing de ejemplo para demostración
const PHISHING_EXAMPLE = {
  sender:  "soporte@banco-seguro.tk",
  subject: "URGENTE: Su cuenta ha sido suspendida",
  body:
`Estimado cliente,

Hemos detectado actividad sospechosa en su cuenta bancaria. Por su seguridad, su cuenta ha sido temporalmente SUSPENDIDA.

Para evitar que su cuenta sea eliminada permanentemente, debe verificar sus datos de acceso URGENTEMENTE en las próximas 24 horas.

Haga clic aquí para verificar: http://bit.ly/verifica-banco
Ingrese su contraseña y número de tarjeta para continuar.

Atentamente,
Banco Internacional de Seguridad`,
  url: "",
};

// ═══════════════════════════════════════════════════════
//  Utilidades
// ═══════════════════════════════════════════════════════

function esc(s) {
  // Escapa también comillas: hardening por si algún valor termina
  // interpolado en un contexto de atributo HTML.
  return String(s ?? "")
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

// Sufijos públicos compuestos más comunes (subconjunto de la Public Suffix
// List). Sin esto, "mail.banco.com.ar" se trataba como si "com.ar" fuera el
// dominio organizacional → DMARC mal consultado y subdominios mal contados.
const MULTI_PART_TLDS = new Set([
  // Argentina
  "com.ar","gob.ar","gov.ar","org.ar","net.ar","edu.ar","mil.ar","tur.ar",
  // Latinoamérica
  "com.mx","gob.mx","org.mx","edu.mx","com.br","gov.br","org.br","net.br",
  "edu.br","com.co","gov.co","edu.co","com.pe","gob.pe","edu.pe","com.cl",
  "gob.cl","com.uy","gub.uy","edu.uy","com.py","gov.py","com.bo","gob.bo",
  "com.ec","gob.ec","com.ve","gob.ve","com.do","gob.do","com.gt","gob.gt",
  "com.pa","gob.pa","com.sv","gob.sv","com.ni","gob.ni","com.hn","gob.hn",
  "com.cr","go.cr","com.cu","gob.cu",
  // Resto del mundo (frecuentes)
  "co.uk","org.uk","gov.uk","ac.uk","me.uk","com.es","org.es","gob.es",
  "edu.es","nom.es","com.au","gov.au","net.au","org.au","co.nz","govt.nz",
  "co.jp","or.jp","ne.jp","co.in","gov.in","net.in","org.in","com.cn",
  "gov.cn","net.cn","org.cn","co.za","gov.za","com.tr","gov.tr",
]);

/**
 * Cantidad de etiquetas que ocupa el sufijo público (1 para ".com",
 * 2 para ".com.ar") y dominio organizacional resultante.
 * Ej: "mail.banco.com.ar" → { suffixLen: 2, orgDomain: "banco.com.ar" }
 */
function getDomainInfo(domain) {
  const parts = domain.split(".");
  const lastTwo = parts.slice(-2).join(".");
  const suffixLen = parts.length > 2 && MULTI_PART_TLDS.has(lastTwo) ? 2 : 1;
  const orgLen = Math.min(parts.length, suffixLen + 1);
  return { suffixLen, orgDomain: parts.slice(-orgLen).join(".") };
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({length: m+1}, (_,i) =>
    Array.from({length: n+1}, (_,j) => i===0 ? j : j===0 ? i : 0));
  for (let i=1; i<=m; i++)
    for (let j=1; j<=n; j++)
      dp[i][j] = a[i-1]===b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[m][n];
}

function extractUrls(text) {
  const re = /https?:\/\/[^\s<>"{}|\\^`\[\]'"]+/gi;
  const raw = text.match(re) || [];
  return [...new Set(raw.map(u => u.replace(/[.,;:!?)\]>»]+$/, "")))];
}

function detectShorteners(urls) {
  return urls.filter(url => {
    try {
      const host = new URL(url).hostname.replace(/^www\./, "");
      return URL_SHORTENERS.has(host);
    } catch { return false; }
  });
}

/**
 * Detecta la técnica de suplantación via @ en URLs.
 * En "https://sitio-falso@host-real.com/", el navegador ignora todo
 * lo anterior al @ y navega al host-real. El usuario cree ver el sitio falso.
 * Devuelve { fakeHost, realHost } o null si no hay suplantación.
 */
function detectUrlSpoofing(url) {
  try {
    // Extraer la parte de autoridad (entre :// y el primer /)
    const m = url.match(/^https?:\/\/([^/?#]+)/);
    if (!m) return null;
    const authority = m[1];
    const atIdx = authority.lastIndexOf("@");
    if (atIdx === -1) return null;
    const fakeHost = decodeURIComponent(authority.slice(0, atIdx));
    const realHost = authority.slice(atIdx + 1);
    if (!realHost) return null;
    return { fakeHost, realHost };
  } catch { return null; }
}

/**
 * Devuelve el nombre de la plataforma de email tracker si el dominio
 * coincide, o null si no es un tracker conocido.
 */
function getEmailTracker(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    for (const [domain, name] of Object.entries(EMAIL_TRACKER_DOMAINS)) {
      if (host === domain || host.endsWith("." + domain)) return name;
    }
  } catch {}
  return null;
}

/**
 * Detecta si una URL usa un parámetro de redirect con contenido cifrado/ofuscado.
 * Patrón: parámetro de intención de redirect (src, dest, data…) con valor
 * largo en base64 que NO decodifica como URL ni como texto ASCII legible.
 * Es común en redirectores de phishing avanzados que ocultan el destino final.
 */
function hasObfuscatedRedirectParam(url) {
  const REDIRECT_INTENT = new Set([
    "src", "source", "data", "d", "dest", "destination",
    "r", "redir", "redirect", "out", "go", "goto", "to",
    "forward", "fwd", "link", "target", "href", "next"
  ]);
  try {
    const parsed = new URL(url);
    for (const [key, v] of parsed.searchParams) {
      if (!REDIRECT_INTENT.has(key.toLowerCase())) continue;
      if (v.length < 40) continue;
      if (!/^[A-Za-z0-9+/=_-]+$/.test(v)) continue;
      // Intentar decodificar: si el resultado NO es URL ni texto ASCII legible → cifrado
      let isReadable = false;
      for (const variant of [v.replace(/-/g, "+").replace(/_/g, "/"), v]) {
        try {
          const decoded = atob(variant);
          if (/^https?:\/\//i.test(decoded)) { isReadable = true; break; }
          if ([...decoded].every(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127)) {
            isReadable = true; break;
          }
        } catch {}
      }
      if (!isReadable) return true; // bytes binarios → contenido cifrado
    }
  } catch {}
  return false;
}

/**
 * Intenta decodificar la URL de destino real a partir de URLs de tracking
 * de plataformas conocidas (Customer.io, SendGrid, etc.).
 * Devuelve la URL real o null si no se pudo extraer.
 */
function decodeTrackerRealUrl(url) {
  try {
    const parsed = new URL(url);
    const host   = parsed.hostname;

    // Customer.io: GET /e/c/{base64json}/{hmac}
    // El payload base64 contiene { href, email_id, link_id, ... }
    if (host.includes("customeriomail.com") || host.includes("cio-sb.com")) {
      const m = parsed.pathname.match(/\/e\/c\/([A-Za-z0-9+/=_-]+?)(?:\/|$)/);
      if (m) {
        // base64url → base64 estándar
        const b64     = m[1].replace(/-/g, "+").replace(/_/g, "/");
        const payload = JSON.parse(atob(b64));
        if (payload?.href?.startsWith("http")) return payload.href;
      }
    }

    // SendGrid click tracking: ?upn=<base64url>
    if (host.includes("sendgrid.net") || host === "sgo.to") {
      const upn = parsed.searchParams.get("upn");
      if (upn) {
        const raw = atob(upn.replace(/-/g, "+").replace(/_/g, "/"));
        if (raw.startsWith("http")) return raw;
      }
    }

    // Genérico paso 1: parámetros habituales con valor directo
    for (const p of ["url", "u", "redirect", "dest", "destination", "link",
                     "href", "goto", "target", "r", "src", "source", "ref",
                     "return", "next", "forward", "to", "out", "go"]) {
      const v = parsed.searchParams.get(p);
      if (!v) continue;
      // Valor directo (ya es una URL)
      if (/^https?:\/\//i.test(v)) return v;
      // URL-encode anidada
      try {
        const dec = decodeURIComponent(v);
        if (/^https?:\/\//i.test(dec)) return dec;
      } catch {}
    }

    // Genérico paso 2: cualquier parámetro cuyo valor parezca base64
    // y se decodifique como una URL válida.
    // Cubre redirectores que codifican el destino, ej: ?src=aHR0cHM6Ly8...
    for (const [, v] of parsed.searchParams) {
      if (v.length < 16) continue;
      if (!/^[A-Za-z0-9+/=_-]+$/.test(v)) continue; // solo chars base64 válidos
      for (const variant of [
        v.replace(/-/g, "+").replace(/_/g, "/"),  // base64url → estándar
        v,                                          // base64 estándar directo
      ]) {
        try {
          const decoded = atob(variant);
          if (/^https?:\/\//i.test(decoded)) {
            new URL(decoded); // valida que sea URL bien formada
            return decoded;
          }
        } catch {}
      }
    }
  } catch {}
  return null;
}

// ═══════════════════════════════════════════════════════
//  Heurística de URL (independiente de listas negras)
// ═══════════════════════════════════════════════════════
// Estas funciones detectan señales de phishing que los blocklists NO ven en
// campañas nuevas (zero-day): un dominio recién creado o un acortador nuevo
// no está todavía en Google Safe Browsing / URLhaus / VirusTotal, así que
// salen como "limpios". La heurística añade una capa de sospecha estructural.

/**
 * Extrae direcciones de correo incrustadas en la RUTA, QUERY o FRAGMENTO de
 * una URL (no en la autoridad user@host, que ya cubre detectUrlSpoofing).
 * Un email dentro de los parámetros es una señal fuerte de phishing dirigido:
 * el atacante pre-rellena el formulario con la víctima o rastrea quién hizo
 * clic. Ej.: https://shortlink.uk/x?operaciones@empresa.com=...
 * Decodifica %40 → @ para no perder emails ofuscados.
 */
function extractEmbeddedEmails(url) {
  let rest = url;
  try {
    const u = new URL(url);
    // Solo ruta + query + fragmento: se descarta la autoridad (user:pass@host).
    rest = (u.pathname || "") + (u.search || "") + (u.hash || "");
  } catch { /* si no parsea, se escanea la cadena completa */ }

  const variants = [rest];
  try { variants.push(decodeURIComponent(rest)); } catch {}

  const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
  const out = new Set();
  for (const text of variants) {
    for (const m of text.match(EMAIL_RE) || []) out.add(m.toLowerCase());
  }
  return [...out];
}

/**
 * Heurística genérica de acortador para los que NO están en URL_SHORTENERS.
 * Patrón: nombre de host que sugiere acortamiento (short/tiny/link/url/clic…)
 * + una única ruta corta y alfanumérica (ej. /1x1Ur). Señal DÉBIL (puntaje
 * bajo) por riesgo de falsos positivos: muchos sitios legítimos usan rutas
 * cortas, por eso se exige además que el nombre del host sea sugerente.
 */
function looksLikeGenericShortener(url) {
  try {
    const u = new URL(url);
    const host = u.hostname.replace(/^www\./, "");
    if (URL_SHORTENERS.has(host)) return false; // ya cubierto por la lista fija
    const segs = u.pathname.split("/").filter(Boolean);
    const oneShortSeg = segs.length === 1 && /^[A-Za-z0-9_-]{4,14}$/.test(segs[0]);
    if (!oneShortSeg) return false;
    // Nombre claramente de acortador. Se evitan substrings ambiguos ("tin" en
    // tinder, "url" en figural…): solo stems inequívocos, o un host muy corto
    // (≤5 chars) bajo un TLD típico de acortadores (.ly/.gg/.gd/.id/.to…).
    const strongName =
      /(short|shorten|tinyurl|cutt|kutt|redir|shrink|snip|trimurl)/i.test(host) ||
      /^[a-z0-9]{1,5}\.(ly|gg|gd|id|to|cc|sh|me|it|tl|ws|cm)$/i.test(host);
    return strongName;
  } catch { return false; }
}

/**
 * Motor heurístico: recibe las URLs originales + los destinos descubiertos
 * (redirects del servidor, trackers decodificados, parámetros ?url=) y
 * devuelve, por URL, una lista de señales con puntaje. Hace además consultas
 * RDAP/WHOIS de antigüedad por dominio organizacional único (con tope, para
 * no disparar decenas de peticiones).
 *
 * Devuelve { perUrl: Map<url, {score, signals:[{label,score}]}>, ageByDomain }.
 */
async function analyzeUrlHeuristics(allUrls, urlResult, redirectInfo, trackerInfo) {
  const perUrl = new Map();
  const add = (url, label, score) => {
    if (!url) return;
    if (!perUrl.has(url)) perUrl.set(url, { score: 0, signals: [] });
    const e = perUrl.get(url);
    if (e.signals.some(s => s.label === label)) return; // sin duplicados
    e.signals.push({ label, score });
    e.score = Math.min(100, e.score + score); // señales independientes suman (cap 100)
  };

  // Conjunto de URLs a inspeccionar: originales + destinos descubiertos.
  const urlsToInspect = new Set(allUrls || []);
  if (redirectInfo) for (const dest of redirectInfo.values()) urlsToInspect.add(dest);
  if (trackerInfo)  for (const t of trackerInfo.values()) if (t?.realUrl) urlsToInspect.add(t.realUrl);
  for (const r of (urlResult?.results || [])) {
    for (const hop of (r.redirectChain || [])) urlsToInspect.add(hop);
  }

  // ── Señales sin red (síncronas) ──
  for (const url of urlsToInspect) {
    const emails = extractEmbeddedEmails(url);
    if (emails.length) {
      add(url, `Email incrustado en la URL (${emails[0]}) — típico de phishing dirigido`, 35);
    }
    if (looksLikeGenericShortener(url)) {
      add(url, "Patrón de acortador no listado — el destino real está oculto", 20);
    }
    try {
      const host = new URL(url).hostname.replace(/^www\./, "");
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
        add(url, "El host es una IP literal en lugar de un dominio", 35);
      } else {
        const tld = host.split(".").pop();
        if (SUSPICIOUS_TLDS.has(tld)) add(url, `TLD ".${tld}" de alto abuso en phishing`, 20);
        const { suffixLen } = getDomainInfo(host);
        const sub = host.split(".").length - suffixLen - 1;
        if (sub >= 3) add(url, `${sub} niveles de subdominio (inusual en sitios legítimos)`, 15);
      }
    } catch {}
  }

  // ── Redirects múltiples (cadena descubierta por el servidor) ──
  for (const r of (urlResult?.results || [])) {
    const hops = r.redirectChain?.length || 0;
    if (hops >= 3)      add(r.url, `Cadena de ${hops} redirects HTTP encadenados — ocultamiento del destino`, 35);
    else if (hops === 2) add(r.url, "2 redirects HTTP encadenados antes del destino", 20);
  }

  // ── Antigüedad de dominio vía RDAP/WHOIS (dominio organizacional único) ──
  const orgByUrl  = new Map();
  const orgDomains = new Set();
  for (const url of urlsToInspect) {
    try {
      const host = new URL(url).hostname.replace(/^www\./, "");
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) continue;
      const { orgDomain } = getDomainInfo(host);
      orgByUrl.set(url, orgDomain);
      orgDomains.add(orgDomain);
    } catch {}
  }
  const ageByDomain = new Map();
  const domains = [...orgDomains].slice(0, 12); // tope de consultas RDAP
  await Promise.all(domains.map(async (d) => {
    ageByDomain.set(d, await rdapDomainAge(d));
  }));
  for (const [url, org] of orgByUrl) {
    const age = ageByDomain.get(org);
    if (age == null) continue;
    if (age < 30)       add(url, `Dominio "${org}" registrado hace ${age} día${age === 1 ? "" : "s"} (WHOIS/RDAP)`, 45);
    else if (age < 180) add(url, `Dominio "${org}" registrado hace ~${Math.floor(age / 30)} mes${Math.floor(age / 30) === 1 ? "" : "es"} (WHOIS/RDAP)`, 20);
  }

  return { perUrl, ageByDomain };
}

// ═══════════════════════════════════════════════════════
//  API
// ═══════════════════════════════════════════════════════

// El servidor rechaza bodies > 50 KB (413). Con muchas URLs largas el
// payload puede superarlo, así que se recorta en el cliente con margen.
const MAX_PAYLOAD_BYTES = 45_000;

function capUrlsToPayload(urls, maxBytes = MAX_PAYLOAD_BYTES) {
  const out = [];
  let size = 40; // overhead aproximado del JSON envolvente
  for (const u of urls) {
    size += u.length + 4; // comillas + coma + escapes ocasionales
    if (size > maxBytes) break;
    out.push(u);
  }
  return out;
}

/**
 * Llama a /check. Devuelve el JSON del servidor, o { error } si la
 * respuesta es un error HTTP o un cuerpo de error — antes esos casos
 * dejaban la UI en "AVISO" sin ninguna explicación.
 */
async function apiCheckUrls(urls, useVT = true) {
  const capped = capUrlsToPayload(urls);
  const payload = capped.length === 1 ? { url: capped[0] } : { urls: capped };
  if (!useVT) payload.useVT = false;
  try {
    const resp = await fetch(CHECK_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data || data.error) {
      return { error: data?.error || `Error del servidor (HTTP ${resp.status})` };
    }
    if (capped.length < urls.length) {
      data.note = (data.note || "") +
        ` Por límite de tamaño solo se enviaron ${capped.length} de ${urls.length} URLs al servidor.`;
    }
    return data;
  } catch {
    return { error: "No se pudo contactar con el servidor de verificación." };
  }
}

async function dnsHasMX(domain) {
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`,
      { headers: { Accept: "application/dns-json" } }
    );
    const d = await r.json();
    return Array.isArray(d.Answer) && d.Answer.length > 0;
  } catch { return null; }
}

/**
 * Verifica si el dominio tiene registro SPF en sus TXT.
 * SPF (Sender Policy Framework) indica qué servidores están autorizados
 * a enviar correo en nombre del dominio.
 * Devuelve:
 *   true           → SPF válido
 *   "permissive"   → SPF existe pero con +all (permite CUALQUIER emisor — inseguro)
 *   false          → sin registro SPF
 *   null           → error de consulta
 */
async function dnsHasSPF(domain) {
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=TXT`,
      { headers: { Accept: "application/dns-json" } }
    );
    const d = await r.json();
    if (!Array.isArray(d.Answer)) return null;
    const spfRec = d.Answer.find(
      (rec) => typeof rec.data === "string" && rec.data.includes("v=spf1")
    );
    if (!spfRec) return false;
    // "+all" significa que cualquier servidor puede enviar como este dominio → tan inseguro como no tener SPF
    if (/\+all\b/.test(spfRec.data)) return "permissive";
    return true;
  } catch { return null; }
}

/**
 * Consulta el registro DMARC de un FQDN dado.
 * Devuelve true si existe, false si no hay registro, null si hubo error.
 */
async function _queryDmarcTxt(fqdn) {
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(fqdn)}&type=TXT`,
      { headers: { Accept: "application/dns-json" } }
    );
    const d = await r.json();
    if (!Array.isArray(d.Answer)) return null;
    if (d.Answer.length === 0) return false;
    return d.Answer.some(
      (rec) => typeof rec.data === "string" && rec.data.includes("v=DMARC1")
    );
  } catch { return null; }
}

/**
 * Verifica si el dominio tiene política DMARC.
 * Implementa el fallback al dominio organizacional según RFC 7489 §6.6.3:
 * si subdomain.empresa.com no tiene _dmarc, busca en _dmarc.empresa.com.
 * Esto evita falsos "Sin política DMARC" en dominios de envío como
 * mail.spotify.com o notifications.paypal.com, que heredan la política
 * del dominio raíz.
 */
async function dnsHasDMARC(domain) {
  // Intento 1: dominio exacto
  const direct = await _queryDmarcTxt("_dmarc." + domain);
  if (direct !== false) return direct; // true (encontrado) o null (error de red)

  // Intento 2: dominio organizacional, respetando sufijos compuestos.
  // Antes: slice(-2) convertía "mail.banco.com.ar" en "com.ar" → consulta
  // inútil y falso "Sin DMARC". Ahora: → "banco.com.ar".
  const { orgDomain } = getDomainInfo(domain);
  if (orgDomain !== domain) {
    return _queryDmarcTxt("_dmarc." + orgDomain);
  }
  return false;
}

/**
 * Consulta la antigüedad del dominio vía RDAP (rdap.org bootstrap).
 * Devuelve la edad en días, o null si no se puede determinar.
 */
async function rdapDomainAge(domain) {
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), 8000);
    let resp;
    try {
      resp = await fetch(
        `https://rdap.org/domain/${encodeURIComponent(domain)}`,
        { signal: ctrl.signal }
      );
    } finally {
      clearTimeout(tid);
    }
    if (!resp.ok) return null;
    const data = await resp.json();
    const regEvent = (data.events || []).find(
      (e) => e.eventAction === "registration"
    );
    if (!regEvent?.eventDate) return null;
    const ageDays = Math.floor(
      (Date.now() - new Date(regEvent.eventDate).getTime()) / 86_400_000
    );
    return ageDays;
  } catch { return null; }
}

// ═══════════════════════════════════════════════════════
//  Analizadores
// ═══════════════════════════════════════════════════════

async function analyzeSender(raw) {
  const email = raw.trim().toLowerCase();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return {
      state: "danger", email: raw, score: 80,
      headline: "Formato de email inválido",
      stats: null,
      issues: ["El texto no tiene estructura de dirección de correo electrónico."],
    };
  }

  const atIdx = email.lastIndexOf("@");
  const local  = email.slice(0, atIdx);
  const domain = email.slice(atIdx + 1);
  const parts  = domain.split(".");
  const tld    = parts[parts.length - 1];

  const issues = [];
  let score = 0;

  if (SUSPICIOUS_TLDS.has(tld)) {
    issues.push(`TLD ".${tld}" muy usado en dominios gratuitos de spam y phishing.`);
    score += 35;
  }

  let typoOf = null;
  for (const d of COMMON_DOMAINS) {
    const dist = levenshtein(domain, d);
    if (dist > 0 && dist <= 2) { typoOf = d; break; }
  }
  if (typoOf) {
    issues.push(`"${domain}" es muy similar a "${typoOf}" — posible dominio falso (typosquatting).`);
    score += 60;
  }

  // Subdominios: descontar el sufijo público (".com" = 1 etiqueta,
  // ".com.ar" = 2) y el dominio en sí. "mail.banco.com.ar" tiene 1 subdominio.
  const { suffixLen } = getDomainInfo(domain);
  const subLevels = Math.max(0, parts.length - suffixLen - 1);
  if (subLevels >= 2) {
    issues.push(`${subLevels} niveles de subdominio (inusual en remitentes legítimos).`);
    score += 20;
  }

  if (/[0-9][a-z]|[a-z][0-9]/i.test(parts[0])) {
    issues.push("Mezcla de números y letras en el nombre de dominio (patrón frecuente en imitaciones).");
    score += 20;
  }

  // Detectar Punycode / ataque de homógrafo
  if (domain.includes("xn--")) {
    issues.push("El dominio usa codificación Punycode — posible ataque de homógrafo (caracteres visualmente idénticos al dominio real).");
    score += 30;
  }

  // Consultar MX, SPF, DMARC y antigüedad en paralelo para ahorrar tiempo
  const [mx, domainAge, spf, dmarc] = await Promise.all([
    dnsHasMX(domain),
    rdapDomainAge(domain),
    dnsHasSPF(domain),
    dnsHasDMARC(domain),
  ]);

  let mxText;
  if (mx === true) {
    mxText = "Registros MX encontrados";
  } else if (mx === false) {
    mxText = "Sin registros MX";
    issues.push("El dominio no tiene registros de correo (MX): en la práctica no puede enviar emails legítimos.");
    score += 50;
  } else {
    mxText = "No se pudo consultar";
  }

  let ageText = "No se pudo consultar";
  if (domainAge !== null) {
    if (domainAge < 30) {
      ageText = `${domainAge} días ⚠`;
      issues.push(`Dominio registrado hace solo ${domainAge} día${domainAge === 1 ? "" : "s"} — los dominios de phishing suelen ser muy recientes.`);
      score += 40;
    } else if (domainAge < 180) {
      const m = Math.floor(domainAge / 30);
      ageText = `~${m} mes${m === 1 ? "" : "es"} ⚠`;
      issues.push(`El dominio fue registrado hace menos de 6 meses (${domainAge} días), inusual para entidades legítimas.`);
      score += 15;
    } else {
      const years = Math.floor(domainAge / 365);
      const months = Math.floor((domainAge % 365) / 30);
      ageText = years > 0
        ? `${years} año${years > 1 ? "s" : ""}`
        : `${months} mes${months !== 1 ? "es" : ""}`;
    }
  }

  let spfText;
  if (spf === true) {
    spfText = "Registro SPF encontrado";
  } else if (spf === "permissive") {
    spfText = "SPF con +all ⚠ (inseguro)";
    issues.push("El dominio tiene SPF pero usa \"+all\" — permite que cualquier servidor envíe correos como este dominio. Es tan inseguro como no tener SPF.");
    score += 20;
  } else if (spf === false) {
    spfText = "Sin registro SPF ⚠";
    issues.push("El dominio no tiene registro SPF — cualquiera puede enviar correos suplantándolo.");
    score += 20;
  } else {
    spfText = "No se pudo consultar";
  }

  let dmarcText;
  if (dmarc === true) {
    dmarcText = "Política DMARC encontrada";
  } else if (dmarc === false) {
    dmarcText = "Sin política DMARC ⚠";
    issues.push("El dominio no tiene política DMARC — los correos falsos que lo suplantan no son rechazados automáticamente.");
    score += 15;
  } else {
    dmarcText = "No se pudo consultar";
  }

  score = Math.min(score, 100);
  const state = score >= 50 ? "danger" : score > 0 ? "warn" : "safe";
  const headline =
    state === "danger" ? "Remitente muy sospechoso" :
    state === "warn"   ? "Señales de alerta" :
                         "Sin señales de alerta";

  return {
    state, email, headline, issues, score,
    stats: [
      ["Local",       local],
      ["Dominio",     domain],
      ["TLD",         "." + tld],
      ["DNS / MX",    mxText],
      ["SPF",         spfText],
      ["DMARC",       dmarcText],
      ["Antigüedad",  ageText],
    ],
  };
}

function analyzeSubject(text) {
  if (!text || !text.trim()) return null;

  const issues = [];
  let score = 0;

  const urgencyRE = [
    /urg[ei]nte/i, /urgencia/i, /inmediata?mente/i,
    /suspendid/i, /bloqueado/i, /cancelado/i, /eliminado/i,
    /24 horas/i, /ahora mismo/i, /de inmediato/i,
  ];
  if (urgencyRE.some(p => p.test(text))) {
    issues.push("El asunto usa lenguaje de urgencia o amenaza para generar alarma.");
    score += 20;
  }

  // Palabras en mayúsculas (3+ letras). Se elimina la puntuación adyacente
  // para que "URGENTE:" o "¡ATENCIÓN!" también cuenten.
  const words = text.split(/\s+/).map(w => w.replace(/[^A-Za-zÁÉÍÓÚÑÜáéíóúñü]/g, ""));
  const capsWords = words.filter(w =>
    w.length >= 3 && /^[A-ZÁÉÍÓÚÑÜ]+$/.test(w)
  );
  if (capsWords.length >= 2) {
    issues.push(`Palabras en mayúsculas: "${capsWords.slice(0, 3).join('", "')}" — táctica para crear alarma.`);
    score += 10;
  }

  // Exceso de exclamaciones
  const excl = (text.match(/!/g) || []).length;
  if (excl >= 2) {
    issues.push(`${excl} signos de exclamación (inusual en correos legítimos).`);
    score += 10;
  }

  score = Math.min(score, 100);
  const state = score >= 25 ? "danger" : score > 0 ? "warn" : "safe";
  return { state, score, issues };
}

function analyzeBody(text) {
  if (!text || !text.trim()) return null;

  const triggered = [];
  let score = 0;

  for (const rule of BODY_RULES) {
    const matched = rule.patterns.some(p => p.test(text));
    if (!matched) continue;

    let desc;
    if (rule.extractNames) {
      const names = rule.patterns
        .filter(p => p.test(text))
        .map(p => { const m = text.match(p); return m ? m[0].trim() : null; })
        .filter(Boolean);
      const unique = [...new Set(names.map(n => n.toLowerCase()))].slice(0, 5);
      desc = rule.desc(unique);
    } else {
      desc = rule.desc();
    }

    triggered.push({ label: rule.label, desc });
    score += rule.score;
  }

  // Palabras en MAYÚSCULAS excesivas
  const capsWords = (text.match(/\b[A-ZÁÉÍÓÚÑÜ]{3,}\b/g) || []);
  if (capsWords.length >= 3) {
    triggered.push({
      label: "Uso excesivo de mayúsculas",
      desc: `Palabras en mayúsculas: ${capsWords.slice(0, 4).join(", ")}${capsWords.length > 4 ? "…" : ""}. Táctica para generar alarma.`,
    });
    score += 10;
  }

  score = Math.min(score, 100);
  const state = score >= 50 ? "danger" : score >= 10 ? "warn" : "safe";
  const headline =
    state === "danger" ? "Contenido muy sospechoso" :
    state === "warn"   ? "Señales de alerta en el texto" :
                         "Texto sin señales evidentes";

  return { state, score, headline, issues: triggered };
}

// ═══════════════════════════════════════════════════════
//  Manejadores de UI
// ═══════════════════════════════════════════════════════

document.getElementById("analyzeBtn").addEventListener("click", async () => {
  const sender  = document.getElementById("senderInput").value.trim();
  const subject = document.getElementById("subjectInput").value.trim();
  const body    = document.getElementById("bodyInput").value.trim();
  const urlOnly = document.getElementById("urlInput").value.trim();

  if (!sender && !subject && !body && !urlOnly) {
    const btn = document.getElementById("analyzeBtn");
    btn.style.background = "var(--warn)";
    document.getElementById("btnText").textContent = "Completa al menos un campo";
    setTimeout(() => {
      btn.style.background = "";
      document.getElementById("btnText").textContent = "Analizar";
    }, 2000);
    return;
  }

  const btn = document.getElementById("analyzeBtn");
  btn.disabled = true;
  btn.classList.add("loading");
  document.getElementById("btnText").textContent = "Analizando…";

  try {
    const useVT = document.getElementById("vtToggle").checked;

    const urlsFromBody = body ? extractUrls(body) : [];
    const allUrls = [...new Set([...urlsFromBody, ...(urlOnly ? [urlOnly] : [])])];
    const shorteners = detectShorteners(allUrls);

    // Detectar URLs con suplantación via @ (ej: hotmail.com@sitio-malicioso.com)
    const spoofedUrls = new Map(); // url → { fakeHost, realHost }
    for (const url of allUrls) {
      const spoof = detectUrlSpoofing(url);
      if (spoof) spoofedUrls.set(url, spoof);
    }

    // Detectar URLs de plataformas de email tracking y decodificar su destino real
    const trackerInfo    = new Map(); // trackerUrl → { name, realUrl }
    const realUrlToTracker = new Map(); // realUrl → trackerUrl (URLs que vienen de un tracker)
    for (const url of allUrls) {
      const trackerName = getEmailTracker(url);
      if (trackerName) {
        const realUrl = decodeTrackerRealUrl(url);
        trackerInfo.set(url, { name: trackerName, realUrl });
        if (realUrl && !allUrls.includes(realUrl)) {
          realUrlToTracker.set(realUrl, url);
        }
      }
    }
    // Verificar también las URLs de destino real (para ver si SON maliciosas)
    // Decodificar redirects genéricos: cualquier URL con ?url= (u otros parámetros comunes)
    // que NO sea ya un tracker conocido. Permite detectar destinos ocultos en
    // redirectores gubernamentales o corporativos (ej: smail.chaco.gob.ar).
    const redirectInfo = new Map(); // url original → url de destino final
    for (const url of allUrls) {
      if (!trackerInfo.has(url)) {
        const realUrl = decodeTrackerRealUrl(url);
        if (realUrl && realUrl !== url && !allUrls.includes(realUrl)) {
          redirectInfo.set(url, realUrl);
        }
      }
    }

    // Segundo paso: re-procesar los destinos decodificados por si también
    // contienen una URL oculta (cadena multi-nivel).
    // Ej: smail.gob.ar/?url=videos.guidemesupport.com/?src=<base64>
    //   → paso 1: smail → videos
    //   → paso 2: videos → mdayanahsan.online (al decodificar src=<base64>)
    for (const [origUrl, destUrl] of [...redirectInfo]) {
      if (!trackerInfo.has(destUrl)) {
        const realUrl2 = decodeTrackerRealUrl(destUrl);
        if (realUrl2 && realUrl2 !== destUrl) {
          redirectInfo.set(origUrl, realUrl2); // actualizar al destino final
        }
      }
    }

    const urlsToCheck = [
      ...allUrls,
      ...[...realUrlToTracker.keys()],
      ...[...redirectInfo.values()].filter(u => !allUrls.includes(u)),
    ];

    const [senderResult, urlResponse] = await Promise.all([
      sender     ? analyzeSender(sender) : null,
      urlsToCheck.length > 0 ? apiCheckUrls(urlsToCheck, useVT) : null,
    ]);

    // Separar respuesta válida de error del servidor (413, 403, 5xx, red…)
    const urlError  = urlResponse?.error || null;
    const urlResult = urlError ? null : urlResponse;

    const subjectResult = analyzeSubject(subject);
    const bodyResult    = analyzeBody(body);

    // Heurística propia (acortadores, redirects múltiples, emails incrustados,
    // dominios jóvenes vía WHOIS/RDAP). No depende de las listas negras: aporta
    // sospecha estructural cuando el servidor dice "limpia".
    const urlHeuristics = allUrls.length > 0
      ? await analyzeUrlHeuristics(allUrls, urlResult, redirectInfo, trackerInfo)
      : null;

    renderResults({ senderResult, subjectResult, bodyResult, urlResult, urlError, allUrls, shorteners, trackerInfo, realUrlToTracker, spoofedUrls, redirectInfo, urlHeuristics });

    setTimeout(() => {
      document.getElementById("results").scrollIntoView({ behavior: "smooth", block: "nearest" });
    }, 100);
  } finally {
    btn.disabled = false;
    btn.classList.remove("loading");
    document.getElementById("btnText").textContent = "Analizar";
  }
});

// Botón de ejemplo
document.getElementById("exampleBtn").addEventListener("click", () => {
  document.getElementById("senderInput").value  = PHISHING_EXAMPLE.sender;
  document.getElementById("subjectInput").value = PHISHING_EXAMPLE.subject;
  document.getElementById("bodyInput").value    = PHISHING_EXAMPLE.body;
  document.getElementById("urlInput").value     = PHISHING_EXAMPLE.url;
  updateCharCounter();
});

// ═══════════════════════════════════════════════════════
//  Análisis de archivos adjuntos (100% local, Web Worker)
// ═══════════════════════════════════════════════════════

const FILE_STEPS = [
  { id: "read",      label: "Cargar el archivo en memoria (sandbox aislado, sin escribir a disco)" },
  { id: "size",      label: "Verificar que el tamaño esté dentro del límite seguro" },
  { id: "hash",      label: "Calcular hash SHA-256" },
  { id: "magic",     label: "Detectar el tipo real del archivo (firma binaria)" },
  { id: "extmatch",  label: "Comparar el tipo real con la extensión declarada" },
  { id: "structure", label: "Analizar la estructura interna (ZIP / PDF / OLE)" },
  { id: "macros",    label: "Buscar macros, scripts o contenido activo embebido" },
  { id: "report",    label: "Generar el informe final" },
];

const MAX_FILE_BYTES = 25 * 1024 * 1024;
const FILE_ANALYSIS_TIMEOUT_MS = 20000;

let activeFileWorker = null;

function fmtSizeUI(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / (1024 * 1024)).toFixed(2) + " MB";
}

function openFileModal() {
  document.getElementById("fileModalOverlay").hidden = false;
  document.body.style.overflow = "hidden";
  // Accesibilidad: mover el foco al botón de cierre al abrir el diálogo
  requestAnimationFrame(() => document.getElementById("fileModalClose").focus());
}

function closeFileModal() {
  document.getElementById("fileModalOverlay").hidden = true;
  document.body.style.overflow = "";
  if (activeFileWorker) {
    activeFileWorker.terminate();
    activeFileWorker = null;
  }
  // Accesibilidad: devolver el foco al botón que abrió el diálogo
  document.getElementById("fileBtn").focus();
}

function renderChecklist() {
  const ul = document.getElementById("fileChecklist");
  ul.innerHTML = FILE_STEPS.map(s => `
    <li id="step-${esc(s.id)}" class="pending">
      <span class="chk-icon">○</span>
      <span class="chk-label">${esc(s.label)}<span class="chk-detail" id="detail-${esc(s.id)}"></span></span>
    </li>`).join("");
}

const STEP_ICONS = { ok: "✓", warn: "!", danger: "✕" };

function updateChecklistStep(id, status, detail) {
  const li = document.getElementById(`step-${id}`);
  if (!li) return;
  li.className = status;
  if (status !== "pending") {
    li.querySelector(".chk-icon").textContent = STEP_ICONS[status] || "✓";
  }
  if (detail) {
    document.getElementById(`detail-${id}`).textContent = detail;
  }
}

// Último informe de archivo analizado (para descarga)
let lastFileReport = null;

function buildFileTextReport(report) {
  const { meta, issues = [], overall = "ok", aborted } = report;
  const ts = new Date().toLocaleString("es-AR", {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
  const verdictLabel = aborted
    ? "ANÁLISIS INTERRUMPIDO"
    : overall === "danger" ? "PELIGRO — se detectaron señales de riesgo importantes"
    : overall === "warn"   ? "ADVERTENCIA — hay señales que requieren precaución"
    : "Sin señales de riesgo evidentes en el análisis local";

  let txt =
`VERIFICA CORREOS — INFORME DE ARCHIVO ADJUNTO
${"═".repeat(58)}
Fecha: ${ts}
Herramienta: https://verifica-correos.netlify.app/

VEREDICTO: ${verdictLabel}

`;

  if (meta) {
    txt += `${"─".repeat(58)}\nMETADATOS DEL ARCHIVO\n\n`;
    if (meta.name)         txt += `  Nombre:                ${meta.name}\n`;
    if (meta.size != null) txt += `  Tamaño:                ${fmtSizeUI(meta.size)}\n`;
    if (meta.detectedType) txt += `  Tipo real detectado:   ${meta.detectedType}\n`;
    if (meta.zipKind)      txt += `  Formato:               ${meta.zipKind}\n`;
    if (meta.declaredType) txt += `  Tipo declarado:        ${meta.declaredType}\n`;
    if (meta.sha256)       txt += `  SHA-256:               ${meta.sha256}\n`;
    txt += "\n";
  }

  if (issues.length) {
    txt += `${"─".repeat(58)}\nSEÑALES DETECTADAS\n\n`;
    issues.forEach(i => {
      const prefix = i.level === "danger" ? "⚠ PELIGRO" : "! AVISO";
      txt += `  [${prefix}] ${i.text}\n\n`;
    });
  } else if (!aborted) {
    txt += `${"─".repeat(58)}\nNo se encontraron extensiones engañosas, macros, ejecutables embebidos\nni contenido activo en el análisis local.\n\n`;
  }

  if (meta?.sha256 && meta.sha256 !== "(no disponible)") {
    txt += `${"─".repeat(58)}\nVerificar hash en VirusTotal:\nhttps://www.virustotal.com/gui/file/${meta.sha256}\n\n`;
  }

  txt += `${"═".repeat(58)}\nNOTA: Resultado orientativo. El análisis se realizó 100% en el navegador,\nsin subir el archivo a ningún servidor.\n\nVerifica Correos — herramienta gratuita y open source\nhttps://verifica-correos.netlify.app/\n`;
  return txt;
}

function downloadFileReport() {
  if (!lastFileReport) return;
  const txt  = buildFileTextReport(lastFileReport);
  const name = lastFileReport.meta?.name ?? "archivo";
  const blob = new Blob([txt], { type: "text/plain;charset=utf-8" });
  const a    = document.createElement("a");
  a.href     = URL.createObjectURL(blob);
  a.download = `informe-archivo-${name}-${new Date().toISOString().slice(0, 10)}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

function renderFileReport(report) {
  const el = document.getElementById("fileReport");
  if (!report) { el.innerHTML = ""; return; }
  lastFileReport = report;
  const { meta, issues = [], overall = "ok", aborted } = report;

  const bannerText = aborted
    ? "Análisis interrumpido"
    : overall === "danger" ? "PELIGRO — se detectaron señales de riesgo importantes"
    : overall === "warn"   ? "ADVERTENCIA — hay señales que requieren precaución"
    : "Sin señales de riesgo evidentes en el análisis local";

  const bannerClass = aborted ? "danger" : overall;

  let html = `<div class="file-report-banner ${bannerClass}">${esc(bannerText)}</div>`;

  if (meta) {
    html += `<dl class="file-report-grid">
      <dt>Nombre</dt><dd>${esc(meta.name ?? "")}</dd>
      ${meta.size != null ? `<dt>Tamaño</dt><dd>${esc(fmtSizeUI(meta.size))}</dd>` : ""}
      ${meta.detectedType ? `<dt>Tipo real detectado</dt><dd>${esc(meta.detectedType)}</dd>` : ""}
      ${meta.zipKind ? `<dt>Formato</dt><dd>${esc(meta.zipKind)}</dd>` : ""}
      ${meta.declaredType ? `<dt>Tipo declarado por el navegador</dt><dd>${esc(meta.declaredType)}</dd>` : ""}
      ${meta.sha256 ? `<dt>SHA-256</dt><dd>${esc(meta.sha256)}</dd>` : ""}
    </dl>`;
  }

  if (issues.length) {
    html += `<ul class="file-report-issues">
      ${issues.map(i => `<li class="${esc(i.level)}">${esc(i.text)}</li>`).join("")}
    </ul>`;
  } else if (!aborted) {
    html += `<div style="font-size:12px;color:var(--muted)">
      No se encontraron extensiones engañosas, macros, ejecutables embebidos ni contenido activo en el análisis local.
      Esto no garantiza que el archivo sea inofensivo — sigue siendo recomendable no abrirlo si no esperabas recibirlo.
    </div>`;
  }

  if (meta?.sha256 && meta.sha256 !== "(no disponible)") {
    html += `<div style="margin-top:12px;font-size:11px;color:var(--muted);line-height:1.5">
      Podés buscar este hash en
      <a href="https://www.virustotal.com/gui/file/${esc(meta.sha256)}" target="_blank" rel="noopener noreferrer" style="color:var(--accent)">VirusTotal</a>
      para ver si algún antivirus lo identifica como malware (esto sí consulta un servicio externo).
    </div>`;
  }

  if (!aborted) {
    html += `<div style="margin-top:16px">
      <button id="downloadFileReportBtn" class="btn-report-txt" type="button">
        ⬇ Descargar informe .txt
      </button>
    </div>`;
  }

  el.innerHTML = html;

  if (!aborted) {
    document.getElementById("downloadFileReportBtn")
      ?.addEventListener("click", downloadFileReport);
  }
}

function startFileAnalysis(file) {
  document.getElementById("fileModalTitle").textContent = `Analizando: ${file.name}`;
  renderChecklist();
  document.getElementById("fileReport").innerHTML = "";
  openFileModal();

  if (file.size > MAX_FILE_BYTES) {
    updateChecklistStep("read", "danger", "No iniciado");
    FILE_STEPS.slice(1).forEach(s => updateChecklistStep(s.id, "danger", "Omitido"));
    renderFileReport({
      meta: { name: file.name, size: file.size },
      issues: [{ level: "danger", text: `El archivo pesa ${fmtSizeUI(file.size)} y supera el límite de ${fmtSizeUI(MAX_FILE_BYTES)}. No se analizó.` }],
      overall: "danger",
      aborted: true,
    });
    return;
  }

  const worker = new Worker("/file-worker.js");
  activeFileWorker = worker;

  const timeout = setTimeout(() => {
    worker.terminate();
    if (activeFileWorker === worker) activeFileWorker = null;
    document.querySelectorAll("#fileChecklist li.pending").forEach(li => {
      li.className = "danger";
      li.querySelector(".chk-icon").textContent = "✕";
    });
    renderFileReport({
      meta: { name: file.name, size: file.size },
      issues: [{ level: "danger", text: "El análisis tardó demasiado y fue cancelado por seguridad." }],
      overall: "danger",
      aborted: true,
    });
  }, FILE_ANALYSIS_TIMEOUT_MS);

  worker.onmessage = (e) => {
    const msg = e.data;
    if (msg.type === "step") {
      updateChecklistStep(msg.id, msg.status, msg.detail);
    } else if (msg.type === "result") {
      clearTimeout(timeout);
      renderFileReport(msg.report);
      // Scroll automático al informe una vez generado
      requestAnimationFrame(() => {
        const report = document.getElementById("fileReport");
        if (report) report.scrollIntoView({ behavior: "smooth", block: "nearest" });
      });
      worker.terminate();
      if (activeFileWorker === worker) activeFileWorker = null;
    }
  };

  worker.onerror = (err) => {
    clearTimeout(timeout);
    document.querySelectorAll("#fileChecklist li.pending").forEach(li => {
      li.className = "danger";
      li.querySelector(".chk-icon").textContent = "✕";
    });
    renderFileReport({
      meta: { name: file.name, size: file.size },
      issues: [{ level: "danger", text: "Ocurrió un error durante el análisis: " + (err.message || "desconocido") }],
      overall: "danger",
      aborted: true,
    });
    worker.terminate();
    if (activeFileWorker === worker) activeFileWorker = null;
  };

  worker.postMessage({ file });
}

document.getElementById("fileBtn").addEventListener("click", () => {
  document.getElementById("fileInput").click();
});

document.getElementById("fileInput").addEventListener("change", (e) => {
  const file = e.target.files?.[0];
  if (!file) return;
  document.getElementById("fileName").textContent = `${file.name} (${fmtSizeUI(file.size)})`;
  startFileAnalysis(file);
});

// ── Drag-and-drop ──────────────────────────────────────
(function setupDragDrop() {
  const dropZone = document.querySelector(".file-drop");
  if (!dropZone) return;

  function handleFile(file) {
    if (!file) return;
    document.getElementById("fileName").textContent = `${file.name} (${fmtSizeUI(file.size)})`;
    startFileAnalysis(file);
  }

  dropZone.addEventListener("dragenter", (e) => {
    e.preventDefault();
    dropZone.classList.add("drag-active");
  });
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault(); // necesario para que "drop" se dispare
    dropZone.classList.add("drag-active");
  });
  dropZone.addEventListener("dragleave", (e) => {
    // Solo quitar la clase si el cursor sale del dropZone (no de un hijo)
    if (!dropZone.contains(e.relatedTarget)) {
      dropZone.classList.remove("drag-active");
    }
  });
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag-active");
    const file = e.dataTransfer.files?.[0];
    handleFile(file);
  });
})();

document.getElementById("fileModalClose").addEventListener("click", closeFileModal);
document.getElementById("fileModalOverlay").addEventListener("click", (e) => {
  if (e.target.id === "fileModalOverlay") closeFileModal();
});
document.addEventListener("keydown", (e) => {
  const overlay = document.getElementById("fileModalOverlay");
  if (overlay.hidden) return;
  if (e.key === "Escape") { closeFileModal(); return; }
  // Focus trap: mientras el modal está abierto, Tab circula solo dentro de él.
  if (e.key === "Tab") {
    const focusables = overlay.querySelectorAll(
      'button, a[href], input, [tabindex]:not([tabindex="-1"])'
    );
    if (focusables.length === 0) return;
    const first = focusables[0];
    const last  = focusables[focusables.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault(); last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault(); first.focus();
    } else if (!overlay.contains(document.activeElement)) {
      e.preventDefault(); first.focus();
    }
  }
});

// Botón limpiar
document.getElementById("clearBtn").addEventListener("click", () => {
  ["senderInput","subjectInput","bodyInput","urlInput"].forEach(id => {
    document.getElementById(id).value = "";
  });
  document.getElementById("vtToggle").checked = false;
  document.getElementById("results").innerHTML = "";
  document.getElementById("fileInput").value = "";
  document.getElementById("fileName").textContent = "Ningún archivo seleccionado";
  updateCharCounter();
});

// Contador de caracteres
function updateCharCounter() {
  const len = document.getElementById("bodyInput").value.length;
  document.getElementById("charCounter").textContent =
    len === 0 ? "0 caracteres" :
    `${len.toLocaleString("es")} caracter${len === 1 ? "" : "es"}`;
}
document.getElementById("bodyInput").addEventListener("input", updateCharCounter);

// Enter en campos de texto
["urlInput","senderInput","subjectInput"].forEach(id => {
  document.getElementById(id).addEventListener("keydown", e => {
    if (e.key === "Enter") document.getElementById("analyzeBtn").click();
  });
});

// ═══════════════════════════════════════════════════════
//  Renderizado
// ═══════════════════════════════════════════════════════

function renderResults({ senderResult, subjectResult, bodyResult, urlResult, urlError, allUrls, shorteners, trackerInfo, realUrlToTracker, spoofedUrls, redirectInfo, urlHeuristics }) {
  const container = document.getElementById("results");
  container.innerHTML = "";

  // Estado global
  const senderState  = senderResult?.state  ?? null;
  const subjectState = subjectResult?.state ?? null;
  const bodyState    = bodyResult?.state    ?? null;
  let urlState = null;
  if (urlResult) {
    urlState = urlResult.verdict === "dangerous" ? "danger"
             : urlResult.verdict === "safe"      ? "safe"
             :                                     "warn";
  } else if (shorteners.length > 0 || (trackerInfo && trackerInfo.size > 0)) {
    urlState = "warn";
  }
  // URLs que el servidor no pudo verificar (hosts internos/privados)
  // nunca dejan el estado en "safe".
  if (urlState === "safe" && urlResult?.results?.some(r => r.verdict === "unverified")) {
    urlState = "warn";
  }
  // Trackers, acortadores y redirects genéricos ocultan o reemplazan el destino real
  // → el banner nunca puede quedar en "safe" cuando alguno está presente.
  if (urlState === "safe" && (
    shorteners.length > 0 ||
    (trackerInfo  && trackerInfo.size  > 0) ||
    (redirectInfo && redirectInfo.size > 0)
  )) {
    urlState = "warn";
  }
  // Puntaje heurístico máximo entre todas las URLs (incluye destinos).
  let heuristicMax = 0;
  if (urlHeuristics?.perUrl) {
    for (const e of urlHeuristics.perUrl.values()) {
      heuristicMax = Math.max(heuristicMax, e.score);
    }
  }
  // La heurística NUNCA debe dejar el banner en "safe": si hay señales
  // estructurales (≥20) aunque las listas negras estén limpias, se baja a "warn".
  if (heuristicMax >= 20 && (urlState === "safe" || urlState === null) && allUrls.length > 0) {
    urlState = "warn";
  }

  // Suplantación via @: siempre peligrosa, sobreescribe cualquier veredicto previo.
  if (spoofedUrls && spoofedUrls.size > 0) {
    urlState = "danger";
  }

  const states = [senderState, subjectState, bodyState, urlState].filter(Boolean);
  const globalState =
    states.includes("danger") ? "danger" :
    states.includes("warn")   ? "warn"   :
    states.length > 0         ? "safe"   : "warn";

  // Puntuación de técnicas de evasión de URL (independiente de las APIs de amenazas)
  // Detecta ocultamiento activo del destino como señal de phishing, no solo URLs maliciosas conocidas.
  const evasionTechniques = [];
  if (spoofedUrls?.size > 0) {
    evasionTechniques.push({ label: "URL falsificada (suplantación via @)", score: 80 });
  }
  if (redirectInfo?.size > 0) {
    let hasObfuscated = false;
    for (const destUrl of redirectInfo.values()) {
      if (hasObfuscatedRedirectParam(destUrl)) { hasObfuscated = true; break; }
    }
    if (hasObfuscated) {
      evasionTechniques.push({ label: "Parámetro de destino cifrado — destino final oculto", score: 55 });
    } else {
      evasionTechniques.push({ label: "Redirect a dominio externo (parámetro ?url=)", score: 30 });
    }
  }
  if (shorteners.length > 0) {
    evasionTechniques.push({ label: "Acortador de URL — destino real no visible", score: 30 });
  }
  if (trackerInfo?.size > 0) {
    evasionTechniques.push({ label: "URL de tracking — enmascara el destino real", score: 20 });
  }
  // Señales heurísticas (emails incrustados, dominios jóvenes, redirects
  // múltiples, TLD de abuso…) agregadas por etiqueta con su puntaje máximo.
  // Se evita duplicar las etiquetas ya presentes en evasionTechniques.
  if (urlHeuristics?.perUrl) {
    const byLabel = new Map();
    for (const e of urlHeuristics.perUrl.values()) {
      for (const s of e.signals) {
        byLabel.set(s.label, Math.max(byLabel.get(s.label) || 0, s.score));
      }
    }
    const shown = new Set(evasionTechniques.map(t => t.label));
    for (const [label, score] of [...byLabel].sort((a, b) => b[1] - a[1])) {
      if (!shown.has(label)) evasionTechniques.push({ label, score });
    }
  }
  const urlTechniqueScore = evasionTechniques.reduce((m, t) => Math.max(m, t.score), 0);

  // Puntaje de riesgo (máximo entre todas las dimensiones)
  const riskScore = Math.min(Math.max(
    senderResult?.score  ?? 0,
    subjectResult?.score ?? 0,
    bodyResult?.score    ?? 0,
    urlState === "danger" ? 85 : urlState === "warn" ? Math.max(35, urlTechniqueScore) : 0,
  ), 100);

  const riskColor = riskScore >= 60 ? "var(--danger)" : riskScore >= 20 ? "var(--warn)" : "var(--accent)";

  // Guardar datos del análisis para generación de informes
  lastAnalysisData = {
    globalState, riskScore, urlState,
    senderResult, subjectResult, bodyResult,
    urlResult, urlError, allUrls,
    shorteners: shorteners || [],
    trackerInfo: trackerInfo || new Map(),
    realUrlToTracker: realUrlToTracker || new Map(),
    spoofedUrls: spoofedUrls || new Map(),
    redirectInfo: redirectInfo || new Map(),
    evasionTechniques: evasionTechniques || [],
    urlHeuristics: urlHeuristics || null,
  };

  const globalHeadlines = {
    danger: "⚠ Se detectaron señales de peligro",
    warn:   "⚡ Hay señales de alerta",
    safe:   "✓ Sin amenazas detectadas",
  };

  // Banner global con barra de riesgo
  const banner = document.createElement("div");
  banner.className = `overall-banner ${globalState}`;
  banner.innerHTML = `
    <div class="banner-top">
      <span class="banner-dot"></span>
      <span>${globalHeadlines[globalState]}</span>
    </div>
    <div class="risk-bar-wrap">
      <div class="risk-bar" style="width:${riskScore}%;background:${riskColor}"></div>
    </div>
    <div class="risk-label">Riesgo estimado: ${riskScore} / 100</div>
  `;
  container.appendChild(banner);

  // Secciones individuales
  if (subjectResult && subjectResult.issues.length > 0) {
    container.appendChild(buildSubjectSection(subjectResult));
  }
  if (senderResult) {
    container.appendChild(buildSenderSection(senderResult));
  }
  if (bodyResult) {
    container.appendChild(buildBodySection(bodyResult));
  }
  if (urlResult || allUrls.length > 0) {
    container.appendChild(buildUrlSection(urlResult, allUrls, shorteners, trackerInfo || new Map(), realUrlToTracker || new Map(), spoofedUrls || new Map(), redirectInfo || new Map(), evasionTechniques || [], urlError, urlHeuristics || null));
  }

  // Nota al pie
  const note = document.createElement("div");
  note.className = "note";
  note.textContent = urlResult?.note || STD_NOTE;
  container.appendChild(note);

  // Botones de informe
  const reportActions = document.createElement("div");
  reportActions.className = "report-actions";
  reportActions.innerHTML = `
    <button class="btn-report-html" id="viewReportBtn" type="button">
      📄 Ver informe completo
    </button>
    <button class="btn-report-txt" id="downloadReportBtn" type="button">
      ⬇ Descargar .txt
    </button>
  `;
  container.appendChild(reportActions);
  document.getElementById("viewReportBtn").addEventListener("click", openHtmlReport);
  document.getElementById("downloadReportBtn").addEventListener("click", downloadTextReport);
}

function buildSubjectSection(s) {
  const label = s.state === "danger" ? "ALERTA" : "AVISO";
  const section = document.createElement("div");
  section.className = `result-section ${s.state}`;
  section.innerHTML = `
    <div class="section-title">
      <div class="section-title-left"><span>📌</span><span>Asunto</span></div>
      <span class="section-badge">${label}</span>
    </div>
    <div class="section-body">
      <ul class="issues-list">
        ${s.issues.map(i => `<li>${esc(i)}</li>`).join("")}
      </ul>
    </div>`;
  return section;
}

function buildSenderSection(s) {
  const label = s.state === "danger" ? "PELIGROSO" : s.state === "warn" ? "ALERTA" : "LIMPIO";
  const section = document.createElement("div");
  section.className = `result-section ${s.state}`;
  section.innerHTML = `
    <div class="section-title">
      <div class="section-title-left"><span>✉</span><span>Remitente</span></div>
      <span class="section-badge">${label}</span>
    </div>
    <div class="section-body">
      <div style="font-family:var(--mono);font-size:12px;word-break:break-all;
                  margin-bottom:${s.stats || s.issues.length ? '12px' : '0'}">
        ${esc(s.email)}
      </div>
      ${s.stats ? `
        <div class="sender-grid">
          ${s.stats.map(([l,v]) => `
            <div class="stat-box">
              <div class="stat-label">${esc(l)}</div>
              <div class="stat-value">${esc(v)}</div>
            </div>`).join("")}
        </div>` : ""}
      ${s.issues.length ? `
        <ul class="issues-list">
          ${s.issues.map(i => `<li>${esc(i)}</li>`).join("")}
        </ul>` : ""}
    </div>`;
  return section;
}

function buildBodySection(b) {
  const issueCount = b.issues.length;
  const label = b.state === "danger" ? "SOSPECHOSO" : b.state === "warn" ? "ALERTA" : "LIMPIO";
  const section = document.createElement("div");
  section.className = `result-section ${b.state}`;
  section.innerHTML = `
    <div class="section-title">
      <div class="section-title-left">
        <span>📄</span>
        <span>Cuerpo (${issueCount} señal${issueCount !== 1 ? "es" : ""})</span>
      </div>
      <span class="section-badge">${label}</span>
    </div>
    <div class="section-body">
      ${issueCount === 0
        ? `<div style="font-size:12px;color:var(--accent)">✓ No se detectaron patrones sospechosos en el texto.</div>`
        : b.issues.map(item => `
            <div class="rule-item">
              <div class="rule-label">${esc(item.label)}</div>
              <div class="rule-desc">${esc(item.desc)}</div>
            </div>`).join("")
      }
    </div>`;
  return section;
}

// ═══════════════════════════════════════════════════════
//  Generación de informes
// ═══════════════════════════════════════════════════════

function buildTextReport(d) {
  const ts = new Date().toLocaleString("es-AR", {
    day:"2-digit", month:"2-digit", year:"numeric",
    hour:"2-digit", minute:"2-digit"
  });
  const globalLabels = {
    danger: "PELIGROSO — Se detectaron señales de peligro",
    warn:   "ALERTA — Hay señales que requieren atención",
    safe:   "LIMPIO — Sin amenazas detectadas",
  };
  let txt =
`VERIFICA CORREOS — INFORME DE ANÁLISIS
${"═".repeat(58)}
Fecha: ${ts}
Herramienta: https://verifica-correos.netlify.app/

VEREDICTO GLOBAL: ${globalLabels[d.globalState] || d.globalState.toUpperCase()}
Riesgo estimado: ${d.riskScore} / 100

`;

  if (d.senderResult) {
    const s = d.senderResult;
    const sl = { danger:"PELIGROSO", warn:"ALERTA", safe:"LIMPIO" }[s.state] || s.state.toUpperCase();
    txt += `${"─".repeat(58)}\nREMITENTE\nDirección: ${s.email}\nEstado: ${sl}\n\n`;
    if (s.stats) s.stats.forEach(([l, v]) => { txt += `  ${(l + ":").padEnd(16)} ${v}\n`; });
    if (s.issues.length) {
      txt += "\nProblemas detectados:\n";
      s.issues.forEach(i => { txt += `  • ${i}\n`; });
    }
    txt += "\n";
  }

  if (d.subjectResult && d.subjectResult.issues.length > 0) {
    const s = d.subjectResult;
    const sl = { danger:"ALERTA", warn:"AVISO", safe:"LIMPIO" }[s.state] || s.state.toUpperCase();
    txt += `${"─".repeat(58)}\nASUNTO\nEstado: ${sl}\n\nProblemas detectados:\n`;
    s.issues.forEach(i => { txt += `  • ${i}\n`; });
    txt += "\n";
  }

  if (d.bodyResult) {
    const b = d.bodyResult;
    const bl = { danger:"SOSPECHOSO", warn:"ALERTA", safe:"LIMPIO" }[b.state] || b.state.toUpperCase();
    txt += `${"─".repeat(58)}\nCUERPO DEL CORREO\nEstado: ${bl}\n`;
    if (b.issues.length) {
      txt += "\nSeñales detectadas:\n";
      b.issues.forEach(i => { txt += `  • [${i.label}]\n    ${i.desc}\n`; });
    } else {
      txt += "  ✓ No se detectaron patrones sospechosos.\n";
    }
    txt += "\n";
  }

  if (d.allUrls && d.allUrls.length > 0) {
    const resultMap = new Map((d.urlResult?.results ?? []).map(r => [r.url, r]));
    const collectHeurTxt = (url) => {
      if (!d.urlHeuristics?.perUrl) return [];
      const acc = [];
      const push = (u) => { const h = d.urlHeuristics.perUrl.get(u); if (h) acc.push(...h.signals); };
      push(url);
      const dest = d.redirectInfo?.get(url); if (dest) push(dest);
      const tr = d.trackerInfo?.get(url); if (tr?.realUrl) push(tr.realUrl);
      for (const hop of (resultMap.get(url)?.redirectChain || [])) push(hop);
      const seen = new Set();
      return acc.filter(s => !seen.has(s.label) && seen.add(s.label));
    };
    txt += `${"─".repeat(58)}\nURLs ANALIZADAS (${d.allUrls.length})\n\n`;
    d.allUrls.forEach(url => {
      const r          = resultMap.get(url);
      const isShortener = d.shorteners?.includes(url);
      const tracker    = d.trackerInfo?.get(url);
      const spoofing   = d.spoofedUrls?.get(url);
      const redirectReal = d.redirectInfo?.get(url);
      const heurSignals = collectHeurTxt(url);
      let verdictText;
      if (spoofing) {
        verdictText = `[FALSIFICADA] Destino real: "${spoofing.realHost}" — no "${spoofing.fakeHost}"`;
      } else if (r?.verdict === "dangerous") {
        const threats = (r.threats || []).map(t => THREAT_LABELS[t] || t).join(", ");
        verdictText = "[AMENAZA] " + (threats || "Detectada por sistemas antimalware");
      } else if (tracker) {
        verdictText = `[TRACKING] ${tracker.name}${tracker.realUrl ? `\n    Destino real: ${tracker.realUrl}` : " (destino no decodificable)"}`;
      } else if (redirectReal) {
        verdictText = `[REDIRECT] Destino: ${redirectReal}`;
      } else if (isShortener) {
        verdictText = "[ACORTADOR] Destino real oculto";
      } else if (heurSignals.length) {
        verdictText = "[HEURÍSTICA] Limpia en listas negras, pero con señales de phishing";
      } else if (r?.verdict === "safe") {
        verdictText = "[LIMPIA] Sin amenazas conocidas";
      } else {
        verdictText = "[SIN VERIFICAR]";
      }
      txt += `  ${url}\n  → ${verdictText}\n`;
      heurSignals.forEach(s => { txt += `      · +${s.score} ${s.label}\n`; });
      txt += "\n";
    });
  }

  txt += `${"═".repeat(58)}\nNOTA IMPORTANTE:\n${STD_NOTE}\n\nVerifica Correos — herramienta gratuita y open source\nhttps://verifica-correos.netlify.app/\n`;
  return txt;
}

function _buildHtmlSection(title, badge, color, bodyHtml) {
  return `
  <div style="margin-bottom:16px;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">
    <div style="display:flex;justify-content:space-between;align-items:center;
                padding:11px 16px;background:#f9fafb;border-bottom:1px solid #e5e7eb">
      <span style="font-weight:600;font-size:14px">${esc(title)}</span>
      <span style="font-size:11px;font-weight:700;padding:3px 9px;border-radius:4px;
                   letter-spacing:.5px;background:${color}22;color:${color}">${esc(badge)}</span>
    </div>
    <div style="padding:14px 16px">${bodyHtml}</div>
  </div>`;
}

function buildHtmlReport(d) {
  const ts = new Date().toLocaleString("es-AR", {
    day:"2-digit", month:"2-digit", year:"numeric",
    hour:"2-digit", minute:"2-digit"
  });
  const globalLabel = { danger:"⚠ PELIGROSO", warn:"⚡ ALERTA", safe:"✓ LIMPIO" }[d.globalState] || "—";
  const globalColor  = { danger:"#dc2626", warn:"#d97706", safe:"#059669" }[d.globalState] || "#6b7280";
  const globalBg     = { danger:"#fef2f2", warn:"#fffbeb", safe:"#f0fdf4" }[d.globalState] || "#f9fafb";
  const globalBorder = { danger:"#fca5a5", warn:"#fcd34d", safe:"#86efac" }[d.globalState] || "#e5e7eb";
  const riskColor    = d.riskScore >= 60 ? "#dc2626" : d.riskScore >= 20 ? "#d97706" : "#059669";

  let sectionsHtml = "";

  // Remitente
  if (d.senderResult) {
    const s = d.senderResult;
    const sc = { danger:"#dc2626", warn:"#d97706", safe:"#059669" }[s.state] || "#6b7280";
    const sl = { danger:"PELIGROSO", warn:"ALERTA", safe:"LIMPIO" }[s.state] || s.state.toUpperCase();
    let bHtml = `<p style="font-family:monospace;font-size:13px;margin-bottom:12px;color:#1f2937;word-break:break-all">${esc(s.email)}</p>`;
    if (s.stats) {
      bHtml += `<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-bottom:12px">` +
        s.stats.map(([l, v]) => `
          <div style="background:#f3f4f6;border-radius:6px;padding:8px 10px">
            <div style="font-size:10px;color:#9ca3af;text-transform:uppercase;margin-bottom:2px">${esc(l)}</div>
            <div style="font-size:12px;font-family:monospace;color:#111">${esc(v)}</div>
          </div>`).join("") + `</div>`;
    }
    if (s.issues.length) {
      bHtml += `<ul style="list-style:none;padding:0">` +
        s.issues.map(i => `<li style="padding:5px 0;border-bottom:1px solid #f3f4f6;font-size:13px;line-height:1.45">
          <span style="color:${sc}">▸ </span>${esc(i)}</li>`).join("") + `</ul>`;
    } else {
      bHtml += `<p style="font-size:13px;color:#059669">✓ Sin señales de alerta en el remitente.</p>`;
    }
    sectionsHtml += _buildHtmlSection("✉ Remitente", sl, sc, bHtml);
  }

  // Asunto
  if (d.subjectResult && d.subjectResult.issues.length > 0) {
    const s = d.subjectResult;
    const sc = { danger:"#dc2626", warn:"#d97706", safe:"#059669" }[s.state] || "#6b7280";
    const sl = { danger:"ALERTA", warn:"AVISO", safe:"LIMPIO" }[s.state] || s.state.toUpperCase();
    const bHtml = `<ul style="list-style:none;padding:0">` +
      s.issues.map(i => `<li style="padding:5px 0;border-bottom:1px solid #f3f4f6;font-size:13px;line-height:1.45">
        <span style="color:${sc}">▸ </span>${esc(i)}</li>`).join("") + `</ul>`;
    sectionsHtml += _buildHtmlSection("📌 Asunto", sl, sc, bHtml);
  }

  // Cuerpo
  if (d.bodyResult) {
    const b = d.bodyResult;
    const bc = { danger:"#dc2626", warn:"#d97706", safe:"#059669" }[b.state] || "#6b7280";
    const bl = { danger:"SOSPECHOSO", warn:"ALERTA", safe:"LIMPIO" }[b.state] || b.state.toUpperCase();
    let bHtml;
    if (!b.issues.length) {
      bHtml = `<p style="color:#059669;font-size:13px">✓ No se detectaron patrones sospechosos.</p>`;
    } else {
      bHtml = b.issues.map(item => `
        <div style="padding:8px 0;border-bottom:1px solid #f3f4f6">
          <div style="font-size:11px;font-weight:700;color:#374151;text-transform:uppercase;
                      letter-spacing:.5px;margin-bottom:3px">${esc(item.label)}</div>
          <div style="font-size:13px;color:#6b7280;line-height:1.5">${esc(item.desc)}</div>
        </div>`).join("");
    }
    sectionsHtml += _buildHtmlSection("📄 Cuerpo del correo", bl, bc, bHtml);
  }

  // URLs
  if (d.allUrls && d.allUrls.length > 0) {
    const resultMap = new Map((d.urlResult?.results ?? []).map(r => [r.url, r]));
    // Señales heurísticas por URL (incluye destinos asociados), deduplicadas.
    const collectHeurReport = (url) => {
      if (!d.urlHeuristics?.perUrl) return [];
      const acc = [];
      const push = (u) => { const h = d.urlHeuristics.perUrl.get(u); if (h) acc.push(...h.signals); };
      push(url);
      const dest = d.redirectInfo?.get(url); if (dest) push(dest);
      const tr = d.trackerInfo?.get(url); if (tr?.realUrl) push(tr.realUrl);
      for (const hop of (resultMap.get(url)?.redirectChain || [])) push(hop);
      const seen = new Set();
      return acc.filter(s => !seen.has(s.label) && seen.add(s.label));
    };
    const urlItemsHtml = d.allUrls.map(url => {
      const r           = resultMap.get(url);
      const isShortener  = d.shorteners?.includes(url);
      const tracker     = d.trackerInfo?.get(url);
      const spoofing    = d.spoofedUrls?.get(url);
      const redirectReal = d.redirectInfo?.get(url);
      const heurSignals = collectHeurReport(url);
      let cls, verdictText, extra = "";
      if (spoofing) {
        cls = "url-danger";
        verdictText = `⚠ URL FALSIFICADA — destino real: "${spoofing.realHost}"`;
      } else if (r?.verdict === "dangerous") {
        const threats = (r.threats || []).map(t => THREAT_LABELS[t] || t).join(", ");
        cls = "url-danger"; verdictText = "⚠ AMENAZA: " + (threats || "detectada");
      } else if (tracker) {
        cls = "url-warn"; verdictText = `⚡ Tracking (${tracker.name})`;
        if (tracker.realUrl) extra = `<div style="font-size:11px;font-family:monospace;color:#6b7280;margin-top:4px;word-break:break-all">→ ${esc(tracker.realUrl)}</div>`;
      } else if (redirectReal) {
        cls = "url-warn"; verdictText = "⚡ Redirect a otro dominio";
        extra = `<div style="font-size:11px;font-family:monospace;color:#6b7280;margin-top:4px;word-break:break-all">→ ${esc(redirectReal)}</div>`;
      } else if (isShortener) {
        cls = "url-warn"; verdictText = "⚡ Acortador de URL";
      } else if (r?.verdict === "safe") {
        cls = "url-safe"; verdictText = "✓ Sin amenazas";
      } else {
        cls = "url-unknown"; verdictText = "? Sin verificar";
      }
      if (heurSignals.length && (cls === "url-safe" || cls === "url-unknown")) {
        cls = "url-warn";
        verdictText = "⚡ Limpia en listas negras, pero con señales heurísticas";
      }
      if (heurSignals.length) {
        extra += `<ul style="margin:6px 0 0;padding-left:16px;font-size:11px;color:#6b7280;line-height:1.5">` +
          heurSignals.map(s => `<li>+${s.score} · ${esc(s.label)}</li>`).join("") + `</ul>`;
      }
      const colors = {
        "url-danger":  { border:"#fca5a5", bg:"#fef2f2", vc:"#dc2626" },
        "url-warn":    { border:"#fcd34d", bg:"#fffbeb", vc:"#d97706" },
        "url-safe":    { border:"#86efac", bg:"#f0fdf4", vc:"#059669" },
        "url-unknown": { border:"#e5e7eb", bg:"#f9fafb", vc:"#9ca3af" },
      }[cls] || { border:"#e5e7eb", bg:"#f9fafb", vc:"#6b7280" };
      return `<div style="padding:9px 12px;border-radius:7px;margin-bottom:8px;
                           border:1px solid ${colors.border};background:${colors.bg}">
        <div style="font-family:monospace;font-size:11px;word-break:break-all;color:#374151">${esc(url)}</div>
        <div style="font-size:12px;font-weight:700;color:${colors.vc};margin-top:4px">${esc(verdictText)}</div>
        ${extra}
      </div>`;
    }).join("");

    const urlLabel = d.urlState === "danger" ? "PELIGROSAS" : d.urlState === "warn" ? "AVISO" : "LIMPIAS";
    const urlColor = { danger:"#dc2626", warn:"#d97706", safe:"#059669" }[d.urlState] || "#6b7280";
    sectionsHtml += _buildHtmlSection(`🔗 URLs (${d.allUrls.length})`, urlLabel, urlColor, urlItemsHtml);
  }

  // Construir el HTML del informe con concatenación de strings para evitar problemas con backticks
  const b = [];
  b.push('<!DOCTYPE html><html lang="es"><head>');
  b.push('<meta charset="UTF-8">');
  b.push('<meta name="viewport" content="width=device-width, initial-scale=1.0">');
  b.push('<title>Informe — Verifica Correos</title>');
  b.push('<style>');
  b.push('*{margin:0;padding:0;box-sizing:border-box}');
  b.push('body{font-family:"Segoe UI",Arial,sans-serif;background:#f3f4f6;color:#111;padding:32px 16px}');
  b.push('.report{max-width:660px;margin:0 auto;background:#fff;border-radius:12px;padding:36px 36px 28px;box-shadow:0 4px 24px rgba(0,0,0,.10)}');
  b.push('.report-tag{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#6b7280;margin-bottom:8px}');
  b.push('.report-title{font-size:22px;font-weight:700;color:#111;margin-bottom:4px}');
  b.push('.report-meta{font-size:12px;color:#9ca3af;margin-bottom:24px}');
  b.push('.report-meta a{color:#9ca3af}');
  b.push('.note-txt{font-size:11px;color:#9ca3af;border-top:1px solid #e5e7eb;padding-top:16px;margin-top:8px;line-height:1.65}');
  b.push('.rpt-footer{text-align:center;font-size:11px;color:#d1d5db;margin-top:20px}');
  b.push('@media print{body{background:#fff;padding:0}.report{box-shadow:none;border-radius:0}}');
  b.push('</style></head><body><div class="report">');
  b.push('<div class="report-tag">// verifica correos &middot; informe de análisis</div>');
  b.push('<div class="report-title">&#128737; Informe de Seguridad</div>');
  b.push('<div class="report-meta">Generado el ' + ts + ' &nbsp;&middot;&nbsp; <a href="https://verifica-correos.netlify.app/" target="_blank">verifica-correos.netlify.app</a></div>');
  // Banner veredicto global
  b.push('<div style="padding:18px 20px;border-radius:10px;margin-bottom:20px;background:' + globalBg + ';border:1.5px solid ' + globalBorder + '">');
  b.push('<div style="font-size:20px;font-weight:700;color:' + globalColor + ';margin-bottom:10px">' + esc(globalLabel) + '</div>');
  b.push('<div style="background:#e5e7eb;border-radius:4px;height:7px;margin-bottom:6px">');
  b.push('<div style="height:7px;border-radius:4px;background:' + riskColor + ';width:' + d.riskScore + '%"></div></div>');
  b.push('<div style="font-size:12px;color:#6b7280">Riesgo estimado: ' + d.riskScore + ' / 100</div></div>');
  b.push(sectionsHtml);
  b.push('<div class="note-txt">' + esc(STD_NOTE) + '</div>');
  b.push('<div class="rpt-footer">Verifica Correos — herramienta gratuita &middot; resultado orientativo</div>');
  b.push('</div></body></html>');
  return b.join("\n");
}

function openHtmlReport() {
  if (!lastAnalysisData) return;
  const html = buildHtmlReport(lastAnalysisData);
  const win = window.open("", "_blank");
  if (!win) {
    alert("Permití ventanas emergentes para ver el informe completo.");
    return;
  }
  win.document.write(html);
  win.document.close();
}

function downloadTextReport() {
  if (!lastAnalysisData) return;
  const txt = buildTextReport(lastAnalysisData);
  const blob = new Blob([txt], { type: "text/plain;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "informe-verifica-correos-" + new Date().toISOString().slice(0,10) + ".txt";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

function buildUrlSection(urlResult, allUrls, shorteners, trackerInfo, realUrlToTracker, spoofedUrls, redirectInfo, evasionTechniques = [], urlError = null, urlHeuristics = null) {
  // Mapa rápido: url → resultado del servidor
  const resultMap = new Map(
    (urlResult?.results ?? allUrls.map(u => ({ url: u, verdict: "unknown", threats: [] })))
      .map(r => [r.url, r])
  );

  // Reúne las señales heurísticas de una URL y de sus destinos asociados
  // (redirect ?url=, tracker decodificado, saltos HTTP del servidor), para
  // que el email incrustado o el dominio joven del destino afloren en la
  // fila de la URL visible. Devuelve la lista deduplicada por etiqueta.
  function collectHeur(url) {
    if (!urlHeuristics?.perUrl) return [];
    const acc = [];
    const push = (u) => { const h = urlHeuristics.perUrl.get(u); if (h) acc.push(...h.signals); };
    push(url);
    const dest = redirectInfo?.get(url); if (dest) push(dest);
    const tr = trackerInfo?.get(url); if (tr?.realUrl) push(tr.realUrl);
    for (const hop of (resultMap.get(url)?.redirectChain || [])) push(hop);
    const seen = new Set();
    return acc.filter(s => !seen.has(s.label) && seen.add(s.label));
  }
  // Agregar resultados de URLs reales decodificadas (si las hay)
  if (urlResult?.results) {
    for (const r of urlResult.results) {
      if (!resultMap.has(r.url)) resultMap.set(r.url, r);
    }
  }

  const displayUrls = allUrls;

  const dangerCount = displayUrls.filter(u => {
    if (spoofedUrls?.has(u) || resultMap.get(u)?.verdict === "dangerous") return true;
    const rDest = redirectInfo?.get(u);
    return rDest && resultMap.get(rDest)?.verdict === "dangerous";
  }).length;
  const realUrlDangerCount = [...realUrlToTracker.keys()]
    .filter(u => resultMap.get(u)?.verdict === "dangerous").length;
  const totalDanger = dangerCount + realUrlDangerCount;

  const hasTrackers   = trackerInfo.size > 0;
  const hasShorteners = shorteners.length > 0;
  const hasRedirects  = redirectInfo && redirectInfo.size > 0;
  let hasHeuristics   = false;
  if (urlHeuristics?.perUrl) {
    for (const e of urlHeuristics.perUrl.values()) {
      if (e.signals.length) { hasHeuristics = true; break; }
    }
  }

  const state = totalDanger > 0 ? "danger"
              : hasShorteners || hasTrackers || hasRedirects || hasHeuristics ? "warn"
              : (urlResult?.verdict === "safe" ? "safe" : "warn");

  const label = totalDanger > 0
    ? `${totalDanger} PELIGROSA${totalDanger > 1 ? "S" : ""}`
    : (urlResult?.verdict === "safe" && !hasTrackers && !hasShorteners && !hasRedirects && !hasHeuristics ? "LIMPIAS" : "AVISO");

  const section = document.createElement("div");
  section.className = `result-section ${state}`;

  const techScore = evasionTechniques.reduce((m, t) => Math.max(m, t.score), 0);
  const evasionHtml = evasionTechniques.length > 0 ? `
    <div style="margin-bottom:10px;padding:10px 12px;border-radius:6px;
                border:1px solid var(--border);background:rgba(0,0,0,.2)">
      <div style="font-family:var(--mono);font-size:10px;color:var(--muted);
                  letter-spacing:.5px;text-transform:uppercase;margin-bottom:6px">
        Técnicas de ocultamiento detectadas
        <span style="float:right;color:${techScore >= 50 ? "var(--danger)" : "var(--warn)"};font-weight:700">
          Indicador de phishing: ${techScore >= 55 ? "ALTO" : techScore >= 30 ? "MODERADO" : "BAJO"} · ${techScore}/100
        </span>
      </div>
      ${evasionTechniques.map(t => `
        <div style="display:flex;align-items:baseline;gap:8px;margin-top:4px">
          <span style="font-family:var(--mono);font-size:10px;
                       color:${t.score >= 50 ? "var(--danger)" : "var(--warn)"};
                       flex-shrink:0">+${t.score}</span>
          <span style="font-size:12px;color:var(--text)">${esc(t.label)}</span>
        </div>`).join("")}
    </div>` : "";

  const itemsHtml = displayUrls.map(url => {
    const r          = resultMap.get(url) ?? { url, verdict: "unknown", threats: [] };
    const isShortener = shorteners.includes(url);
    const tracker    = trackerInfo?.get(url);
    const realUrlResult = tracker?.realUrl ? resultMap.get(tracker.realUrl) : null;
    const spoofing   = spoofedUrls?.get(url);
    const redirectRealUrl    = (!tracker && !spoofing) ? (redirectInfo?.get(url) ?? null) : null;
    const redirectRealResult = redirectRealUrl ? (resultMap.get(redirectRealUrl) ?? null) : null;

    let cls, verdictText;

    if (spoofing) {
      cls = "url-danger";
      verdictText = `⚠ URL FALSIFICADA — aparenta ser "${spoofing.fakeHost}" pero el destino real es "${spoofing.realHost}"`;
    } else if (r.verdict === "dangerous") {
      cls = "url-danger";
      const threats = (r.threats || []).map(t => THREAT_LABELS[t] || t).join(", ");
      verdictText = "⚠ " + (threats || "AMENAZA DETECTADA");
    } else if (tracker) {
      cls = realUrlResult?.verdict === "dangerous" ? "url-danger" : "url-warn";
      verdictText = `⚡ Tracking (${tracker.name}) — el destino real está enmascarado`;
    } else if (redirectRealUrl) {
      const isRealDangerous = redirectRealResult?.verdict === "dangerous";
      const hasDestChain    = (redirectRealResult?.redirectChain?.length ?? 0) > 0;
      const isObfuscated    = hasObfuscatedRedirectParam(redirectRealUrl);
      cls = isRealDangerous ? "url-danger" : "url-warn";
      verdictText = isRealDangerous
        ? "⚠ REDIRIGE A URL PELIGROSA"
        : isObfuscated
        ? "⚠ El destino usa parámetros cifrados — sitio final DESCONOCIDO"
        : hasDestChain
        ? "⚡ Cadena de redirects detectada — destino final no figura en listas negras"
        : "⚡ Redirige a otro dominio (parámetro ?url=) — destino verificado";
    } else if (isShortener) {
      cls = "url-warn";
      verdictText = "⚡ Acortador de URL — el destino real está oculto";
    } else if (r.verdict === "safe") {
      cls = "url-safe";
      verdictText = "✓ Sin amenazas";
    } else if (r.verdict === "unverified") {
      cls = "url-warn";
      verdictText = "⚠ No verificable — apunta a una dirección interna o privada";
    } else {
      cls = "url-unknown";
      verdictText = "? Sin verificar";
    }

    // Señales heurísticas: si la URL salió "limpia"/"sin verificar" en las
    // listas negras pero la heurística encontró señales, se degrada a aviso
    // para que NO se muestre como segura.
    const heurSignals = collectHeur(url);
    if (heurSignals.length && (cls === "url-safe" || cls === "url-unknown")) {
      cls = "url-warn";
      verdictText = "⚡ Sin coincidencias en listas negras, pero con señales heurísticas de phishing";
    }

    let realUrlBlock = "";
    if (tracker) {
      if (tracker.realUrl) {
        let rColor, rText;
        if (realUrlResult?.verdict === "dangerous") {
          const threats = (realUrlResult.threats || []).map(t => THREAT_LABELS[t] || t).join(", ");
          rColor = "var(--danger)";
          rText  = "⚠ " + (threats || "AMENAZA DETECTADA en destino real");
        } else if (realUrlResult?.verdict === "safe") {
          rColor = "var(--accent)";
          rText  = "✓ Sin amenazas";
        } else {
          rColor = "var(--muted)";
          rText  = "? Sin verificar";
        }
        realUrlBlock = `
          <div style="margin-top:8px;padding:8px 10px;border-radius:6px;
                      border:1px solid var(--border);background:rgba(0,0,0,.25)">
            <div style="font-family:var(--mono);font-size:10px;color:var(--muted);
                        margin-bottom:4px;letter-spacing:.5px;text-transform:uppercase">
              → Destino real decodificado
            </div>
            <div class="url-text" style="margin-bottom:4px;color:var(--text)">
              ${esc(tracker.realUrl)}
            </div>
            <div style="font-family:var(--mono);font-size:11px;font-weight:700;
                        color:${rColor}">${esc(rText)}</div>
          </div>`;
      } else {
        realUrlBlock = `
          <div style="margin-top:6px;font-size:11px;color:var(--muted);
                      font-family:var(--mono)">
            ℹ No se pudo decodificar el destino real — abre el enlace con precaución.
          </div>`;
      }
    }

    let redirectBlock = "";
    if (redirectRealUrl) {
      const isObfuscatedDest = hasObfuscatedRedirectParam(redirectRealUrl);
      let rColor, rText;
      if (redirectRealResult?.verdict === "dangerous") {
        const threats = (redirectRealResult.threats || []).map(t => THREAT_LABELS[t] || t).join(", ");
        rColor = "var(--danger)";
        rText  = "⚠ " + (threats || "AMENAZA DETECTADA en destino");
      } else if (redirectRealResult?.verdict === "safe") {
        rColor = "var(--accent)";
        rText  = "✓ Dominio no figura en listas negras";
      } else {
        rColor = "var(--muted)";
        rText  = "? Sin verificar (servidor no disponible)";
      }
      const obfuscatedNote = isObfuscatedDest
        ? `<div style="margin-top:5px;font-family:var(--mono);font-size:10px;color:var(--warn)">
             ⚠ Parámetros cifrados — el destino final dentro del ?src= es desconocido
           </div>`
        : "";
      const destHops = redirectRealResult?.redirectChain ?? [];
      const hopChainHtml = destHops.length > 0
        ? `<div style="margin-top:6px;font-family:var(--mono);font-size:10px;color:var(--muted);letter-spacing:.3px;text-transform:uppercase">
             Saltos HTTP descubiertos por el servidor:
           </div>` +
          destHops.map(hopUrl => `
            <div style="margin-top:3px;padding-left:8px;border-left:2px solid var(--border);
                        font-family:var(--mono);font-size:10px;color:var(--muted)">
              ↳ ${esc(hopUrl)}
            </div>`).join("")
        : "";
      redirectBlock = `
        <div style="margin-top:8px;padding:8px 10px;border-radius:6px;
                    border:1px solid var(--border);background:rgba(0,0,0,.25)">
          <div style="font-family:var(--mono);font-size:10px;color:var(--muted);
                      margin-bottom:4px;letter-spacing:.5px;text-transform:uppercase">
            → Destino decodificado (parámetro ?url=)
          </div>
          <div class="url-text" style="margin-bottom:4px;color:var(--text)">
            ${esc(redirectRealUrl)}
          </div>
          <div style="font-family:var(--mono);font-size:11px;font-weight:700;
                      color:${rColor}">${esc(rText)}</div>
          ${obfuscatedNote}
          ${hopChainHtml}
        </div>`;
    }

    let serverChainBlock = "";
    const serverHops = r.redirectChain;
    if (serverHops?.length > 0) {
      const hopsHtml = serverHops.map(hopUrl => `
        <div style="font-family:var(--mono);font-size:10px;color:var(--muted);
                    margin-top:3px;padding-left:8px;border-left:2px solid var(--border)">
          ↳ ${esc(hopUrl)}
        </div>`).join("");
      serverChainBlock = `
        <div style="margin-top:8px;padding:6px 10px;border-radius:6px;
                    border:1px solid var(--border);background:rgba(0,0,0,.15)">
          <div style="font-family:var(--mono);font-size:10px;color:var(--muted);
                      margin-bottom:4px;letter-spacing:.5px;text-transform:uppercase">
            → Cadena de redirects HTTP (servidor)
          </div>
          ${hopsHtml}
        </div>`;
    }

    let heurBlock = "";
    if (heurSignals.length) {
      const heurMax = heurSignals.reduce((m, s) => Math.max(m, s.score), 0);
      const level = heurMax >= 45 ? "ALTO" : heurMax >= 25 ? "MODERADO" : "BAJO";
      const lvlColor = heurMax >= 45 ? "var(--danger)" : "var(--warn)";
      heurBlock = `
        <div style="margin-top:8px;padding:8px 10px;border-radius:6px;
                    border:1px solid var(--border);background:rgba(0,0,0,.25)">
          <div style="font-family:var(--mono);font-size:10px;color:var(--muted);
                      margin-bottom:4px;letter-spacing:.5px;text-transform:uppercase">
            Análisis heurístico (sin listas negras)
            <span style="float:right;color:${lvlColor};font-weight:700">Indicio: ${level}</span>
          </div>
          ${heurSignals.map(s => `
            <div style="display:flex;align-items:baseline;gap:8px;margin-top:3px">
              <span style="font-family:var(--mono);font-size:10px;flex-shrink:0;
                           color:${s.score >= 45 ? "var(--danger)" : "var(--warn)"}">+${s.score}</span>
              <span style="font-size:12px;color:var(--text)">${esc(s.label)}</span>
            </div>`).join("")}
        </div>`;
    }

    return `<div class="url-item ${cls}">
              <div class="url-text">${esc(url)}</div>
              <div class="url-verdict">${esc(verdictText)}</div>
              ${heurBlock}
              ${realUrlBlock}
              ${redirectBlock}
              ${serverChainBlock}
            </div>`;
  }).join("");

  section.innerHTML = `
    <div class="section-title">
      <div class="section-title-left">
        <span>🔗</span>
        <span>URLs (${displayUrls.length})</span>
      </div>
      <span class="section-badge">${label}</span>
    </div>
    <div class="section-body">
      ${evasionHtml}
      ${itemsHtml}
      ${urlResult?.source ? `
        <div style="font-family:var(--mono);font-size:10px;color:var(--muted);
                    margin-top:10px;letter-spacing:.3px">
          Fuentes consultadas: ${esc(urlResult.source)}
        </div>` : ""}
      ${!urlResult && displayUrls.length > 0 ? `
        <div style="font-size:12px;color:var(--warn);margin-top:8px">
          ⚠ Verificación del servidor no disponible: ${esc(urlError || "no se pudo contactar con el servidor.")}
          El análisis heurístico local sigue siendo válido, pero las URLs no se
          contrastaron con las bases de datos de amenazas.
        </div>` : ""}
    </div>`;
  return section;
}
