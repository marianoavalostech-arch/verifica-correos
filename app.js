// ═══════════════════════════════════════════════════════
//  Constantes
// ═══════════════════════════════════════════════════════

const CHECK_ENDPOINT = "/check";

const STD_NOTE =
  "Resultado orientativo. Ninguna herramienta detecta el 100 % de las amenazas. " +
  "Un correo puede ser peligroso aunque aparezca como limpio. " +
  "Fuentes: Google Safe Browsing, URLhaus (abuse.ch) y análisis heurístico propio.";

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
    ],
    desc: () => "Solicita verificar o actualizar datos de cuenta — táctica central de phishing.",
  },
];

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
  return String(s ?? "")
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
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

    // Genérico: buscar URL de destino en parámetros de query habituales
    for (const p of ["url", "u", "redirect", "dest", "link", "href", "goto", "target", "r"]) {
      const v = parsed.searchParams.get(p);
      if (v?.startsWith("http")) return v;
    }
  } catch {}
  return null;
}

// ═══════════════════════════════════════════════════════
//  API
// ═══════════════════════════════════════════════════════

async function apiCheckUrls(urls, useVT = true) {
  const payload = urls.length === 1 ? { url: urls[0] } : { urls };
  if (!useVT) payload.useVT = false;
  const resp = await fetch(CHECK_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return resp.json();
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
 */
async function dnsHasSPF(domain) {
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=TXT`,
      { headers: { Accept: "application/dns-json" } }
    );
    const d = await r.json();
    return Array.isArray(d.Answer) && d.Answer.some(
      (rec) => typeof rec.data === "string" && rec.data.includes("v=spf1")
    );
  } catch { return null; }
}

/**
 * Verifica si el dominio tiene política DMARC en _dmarc.<domain>.
 * DMARC instruye a los servidores receptores cómo tratar correos
 * que no superan las validaciones SPF/DKIM.
 */
async function dnsHasDMARC(domain) {
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent("_dmarc." + domain)}&type=TXT`,
      { headers: { Accept: "application/dns-json" } }
    );
    const d = await r.json();
    return Array.isArray(d.Answer) && d.Answer.some(
      (rec) => typeof rec.data === "string" && rec.data.includes("v=DMARC1")
    );
  } catch { return null; }
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

  if (parts.length > 3) {
    issues.push(`${parts.length-1} niveles de subdominio (inusual en remitentes legítimos).`);
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

  // Palabras en mayúsculas (3+ letras, solo letras en mayúsculas — excluye números y símbolos)
  const words = text.split(/\s+/);
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
    const urlsToCheck = [...allUrls, ...[...realUrlToTracker.keys()]];

    const [senderResult, urlResult] = await Promise.all([
      sender     ? analyzeSender(sender) : null,
      urlsToCheck.length > 0 ? apiCheckUrls(urlsToCheck, useVT).catch(() => null) : null,
    ]);

    const subjectResult = analyzeSubject(subject);
    const bodyResult    = analyzeBody(body);

    renderResults({ senderResult, subjectResult, bodyResult, urlResult, allUrls, shorteners, trackerInfo, realUrlToTracker, spoofedUrls });

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

// Botón limpiar
document.getElementById("clearBtn").addEventListener("click", () => {
  ["senderInput","subjectInput","bodyInput","urlInput"].forEach(id => {
    document.getElementById(id).value = "";
  });
  document.getElementById("vtToggle").checked = false;
  document.getElementById("results").innerHTML = "";
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

function renderResults({ senderResult, subjectResult, bodyResult, urlResult, allUrls, shorteners, trackerInfo, realUrlToTracker, spoofedUrls }) {
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
  // Trackers y acortadores ocultan el destino real → el banner nunca puede quedar en "safe".
  // Se aplica después del bloque de API para degradar "safe" a "warn" cuando corresponde.
  if (urlState === "safe" && (shorteners.length > 0 || (trackerInfo && trackerInfo.size > 0))) {
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

  // Puntaje de riesgo (máximo entre todas las dimensiones)
  const riskScore = Math.min(Math.max(
    senderResult?.score  ?? 0,
    subjectResult?.score ?? 0,
    bodyResult?.score    ?? 0,
    urlState === "danger" ? 85 : urlState === "warn" ? 35 : 0,
  ), 100);

  const riskColor = riskScore >= 60 ? "var(--danger)" : riskScore >= 20 ? "var(--warn)" : "var(--accent)";

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
    container.appendChild(buildUrlSection(urlResult, allUrls, shorteners, trackerInfo || new Map(), realUrlToTracker || new Map(), spoofedUrls || new Map()));
  }

  // Nota al pie
  const note = document.createElement("div");
  note.className = "note";
  note.textContent = urlResult?.note || STD_NOTE;
  container.appendChild(note);
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

function buildUrlSection(urlResult, allUrls, shorteners, trackerInfo, realUrlToTracker, spoofedUrls) {
  // Mapa rápido: url → resultado del servidor
  const resultMap = new Map(
    (urlResult?.results ?? allUrls.map(u => ({ url: u, verdict: "unknown", threats: [] })))
      .map(r => [r.url, r])
  );
  // Agregar resultados de URLs reales decodificadas (si las hay)
  if (urlResult?.results) {
    for (const r of urlResult.results) {
      if (!resultMap.has(r.url)) resultMap.set(r.url, r);
    }
  }

  // Solo mostramos las URLs originales del usuario (no las decodificadas como items separados)
  // Las decodificadas aparecen inline dentro del item del tracker.
  const displayUrls = allUrls;

  // Peligrosas: solo entre las URLs originales (excluir las decodificadas)
  const dangerCount = displayUrls.filter(u =>
    spoofedUrls?.has(u) || resultMap.get(u)?.verdict === "dangerous"
  ).length;
  // También contar si alguna URL real (decodificada de tracker) es peligrosa
  const realUrlDangerCount = [...realUrlToTracker.keys()]
    .filter(u => resultMap.get(u)?.verdict === "dangerous").length;
  const totalDanger = dangerCount + realUrlDangerCount;

  const hasTrackers   = trackerInfo.size > 0;
  const hasShorteners = shorteners.length > 0;

  const state = totalDanger > 0 ? "danger"
              : hasShorteners || hasTrackers ? "warn"
              : (urlResult?.verdict === "safe" ? "safe" : "warn");

  const label = totalDanger > 0
    ? `${totalDanger} PELIGROSA${totalDanger > 1 ? "S" : ""}`
    : (urlResult?.verdict === "safe" && !hasTrackers && !hasShorteners ? "LIMPIAS" : "AVISO");

  const section = document.createElement("div");
  section.className = `result-section ${state}`;

  const itemsHtml = displayUrls.map(url => {
    const r          = resultMap.get(url) ?? { url, verdict: "unknown", threats: [] };
    const isShortener = shorteners.includes(url);
    const tracker    = trackerInfo?.get(url);   // { name, realUrl } | undefined
    const realUrlResult = tracker?.realUrl ? resultMap.get(tracker.realUrl) : null;
    const spoofing   = spoofedUrls?.get(url);   // { fakeHost, realHost } | undefined

    let cls, verdictText;

    if (spoofing) {
      // La suplantación via @ tiene prioridad — es siempre peligrosa
      cls = "url-danger";
      verdictText = `⚠ URL FALSIFICADA — aparenta ser "${spoofing.fakeHost}" pero el destino real es "${spoofing.realHost}"`;
    } else if (r.verdict === "dangerous") {
      cls = "url-danger";
      const threats = (r.threats || []).map(t => THREAT_LABELS[t] || t).join(", ");
      verdictText = "⚠ " + (threats || "AMENAZA DETECTADA");
    } else if (tracker) {
      // Es un tracker de email — el estado depende también del destino real
      cls = realUrlResult?.verdict === "dangerous" ? "url-danger" : "url-warn";
      verdictText = `⚡ Tracking (${tracker.name}) — el destino real está enmascarado`;
    } else if (isShortener) {
      cls = "url-warn";
      verdictText = "⚡ Acortador de URL — el destino real está oculto";
    } else if (r.verdict === "safe") {
      cls = "url-safe";
      verdictText = "✓ Sin amenazas";
    } else {
      cls = "url-unknown";
      verdictText = "? Sin verificar";
    }

    // Bloque inline del destino real decodificado (solo para trackers)
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

    return `<div class="url-item ${cls}">
              <div class="url-text">${esc(url)}</div>
              <div class="url-verdict">${esc(verdictText)}</div>
              ${realUrlBlock}
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
      ${itemsHtml}
      ${urlResult?.source ? `
        <div style="font-family:var(--mono);font-size:10px;color:var(--muted);
                    margin-top:10px;letter-spacing:.3px">
          Fuentes consultadas: ${esc(urlResult.source)}
        </div>` : ""}
      ${!urlResult && displayUrls.length > 0 ? `
        <div style="font-size:12px;color:var(--muted);margin-top:8px">
          No se pudo contactar con el servidor de verificación.
        </div>` : ""}
    </div>`;
  return section;
}
