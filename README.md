# Verifica Correos

Herramienta web para analizar correos electrónicos sospechosos. Detecta phishing, malware y señales de ingeniería social analizando el remitente, asunto, cuerpo y URLs del correo — incluyendo destinos ocultos detrás de redirectores y cadenas de redireccionamiento.

## Cómo funciona

El análisis se divide en cuatro dimensiones, cada una con un puntaje de 0 a 100. El banner principal muestra el **riesgo estimado** (el máximo entre las cuatro) con una barra de color.

### 1. Remitente

Análisis heurístico del dominio + consultas DNS en el navegador (sin backend):

| Señal | Fuente | Peso |
|---|---|---|
| TLD sospechoso | Lista interna (60+ TLDs) | +35 |
| Typosquatting (ej. `gmai1.com`) | Distancia Levenshtein | +60 |
| Subdominios excesivos | Heurística | +20 |
| Mezcla números/letras en dominio | Heurística | +20 |
| Punycode / ataque de homógrafo | Heurística | +30 |
| Sin registros MX | Cloudflare DoH | +50 |
| Sin registro SPF | Cloudflare DoH | +20 |
| Sin política DMARC | Cloudflare DoH | +15 |
| Dominio < 30 días | RDAP (rdap.org) | +40 |
| Dominio 30–180 días | RDAP (rdap.org) | +15 |

### 2. Asunto

Detecta urgencia, palabras en mayúsculas y exclamaciones.

### 3. Cuerpo

Reglas heurísticas en **español e inglés** para:

| Regla | Ejemplos detectados | Peso |
|---|---|---|
| Urgencia | "urgente", "inmediatamente", "urgent", "action required" | +20 |
| Solicitud de credenciales | "contraseña", "datos bancarios", "CVV" | +45 |
| Amenaza de suspensión | "cuenta bloqueada", "account restricted", "temporarily limited" | +35 |
| Promesa de premio | "ganador", "lotería", "regalo gratis" | +30 |
| Solicitud de verificación | "verificar su cuenta", "verify your identity", "suspicious sign-in" | +30 |
| Promesa de reembolso | "reembolso", "pago pendiente" | +25 |
| Presión para hacer clic | "haga clic", "click here", "verify account access" | +15 |
| Suplantación de marca | PayPal, Netflix, Amazon, American Express, BBVA, MercadoPago, AFIP… | +10 |
| Mayúsculas excesivas | Detección dinámica | +10 |

### 4. URLs

Las URLs se verifican en cuatro pasos:

**Paso 1 — Extracción:** se extraen todas las URLs del cuerpo del correo más cualquier URL introducida manualmente.

**Paso 2 — Decodificación de redirectores:** se detectan y decodifican URLs que ocultan el destino real a través de:
- Parámetros `?url=`, `?redirect=`, `?dest=` y similares (ej. redirectores corporativos o gubernamentales)
- Plataformas de email marketing (Customer.io, SendGrid, Mailchimp, HubSpot, Klaviyo, etc.)
- Suplantación via `@` en la URL (ej. `https://banco.com@sitio-malicioso.com`)
- Acortadores de URL (bit.ly, tinyurl, etc.)

**Paso 3 — Seguimiento de redirects HTTP:** el servidor sigue la cadena de redireccionamientos HTTP (302/301) de cada URL hasta 3 saltos, descubriendo el destino final aunque esté oculto detrás de múltiples intermediarios.

**Paso 4 — Verificación contra APIs:** todas las URLs (originales + destinos descubiertos) se verifican en paralelo contra:

| Fuente | Tipo | API key |
|---|---|---|
| **URLhaus** (abuse.ch) | URLs maliciosas activas | Sí, gratuita (`ABUSECH_AUTH_KEY`) |
| **ThreatFox** (abuse.ch) | IOCs: dominios C2, malware, phishing | Sí, gratuita (`ABUSECH_AUTH_KEY`) |
| **Google Safe Browsing** | Malware, phishing, software no deseado | Sí (`GOOGLE_SAFE_BROWSING_KEY`) |
| **VirusTotal** | +90 motores antivirus | Opcional (`VIRUSTOTAL_API_KEY`) |

> **Nota:** desde 2025, abuse.ch exige autenticación con Auth-Key en sus APIs. La clave se obtiene gratis en [auth.abuse.ch](https://auth.abuse.ch/) y sirve para URLhaus y ThreatFox a la vez. Sin ella, esas dos fuentes se omiten.

## Ejemplo de detección: phishing de American Express

Este correo no habría sido detectado con la versión anterior de la herramienta:

```
De:      mwitcher@fpcwaste.com  (cuenta legítima comprometida)
Asunto:  American Express
Cuerpo:  Account access restricted — Suspicious sign-in attempt detected.
         Verify account access (takes less than two minutes)
URL:     https://smail.chaco.gob.ar/fmlurlsvc/?url=https://videos.guidemesupport.com/...
```

Cadena completa detectada ahora:

```
smail.chaco.gob.ar/?url=...
  └─ (param ?url=) → videos.guidemesupport.com     [verificado contra APIs]
       └─ (HTTP 302) → mdayanahsan.online/amez/    [verificado + TLD .online sospechoso]
```

Resultado: **DANGER — score 80/100** (amenaza +35, verificación +30, clic +15)

## Fuentes externas sin API key (consultadas desde el navegador)

| Servicio | URL | Uso |
|---|---|---|
| Cloudflare DoH | `cloudflare-dns.com/dns-query` | Registros MX, SPF, DMARC |
| RDAP | `rdap.org/domain/<dominio>` | Antigüedad del dominio |

RDAP responde con un redirect 302 al servidor del registro correspondiente (ej. `rdap.verisign.com`); por eso la CSP usa `connect-src https:` en lugar de una lista cerrada de dominios.

## Configuración en Netlify

Variables de entorno (Settings → Environment variables):

| Variable | Descripción | Requerida |
|---|---|---|
| `GOOGLE_SAFE_BROWSING_KEY` | Clave de Google Safe Browsing v4 | Recomendada |
| `ABUSECH_AUTH_KEY` | Auth-Key de abuse.ch (URLhaus + ThreatFox), gratis en [auth.abuse.ch](https://auth.abuse.ch/) | Recomendada |
| `VIRUSTOTAL_API_KEY` | Clave de VirusTotal v3 | Opcional |
| `ALLOWED_ORIGIN` | Dominio permitido en CORS (ej. `https://tu-sitio.netlify.app`) | Recomendada en producción |

Sin ninguna variable, el servidor solo sigue redirects HTTP (sin verificar contra listas negras); el análisis del navegador (heurística, DNS, RDAP) funciona igual.

## Estructura del proyecto

```
├── index.html                    # UI principal
├── app.css                       # Estilos
├── app.js                        # Lógica del cliente (heurística, DNS, decodificación de redirects)
├── netlify/functions/
│   └── check.js                  # Función serverless (APIs de amenazas + seguimiento de redirects HTTP)
├── netlify.toml                  # Configuración de Netlify (alias /check, rate limiting)
└── .env.example                  # Variables de entorno de ejemplo
```

## Límites y rate limiting

- La función serverless acepta hasta **100 URLs por llamada**.
- El seguimiento de redirects HTTP verifica hasta **300 URLs únicas** por llamada (originales + saltos descubiertos).
- Rate limiting: **20 requests por minuto por IP**, configurado en `netlify/functions/check.js` (`exports.config.rateLimit`). Protege la cuota diaria de Google Safe Browsing (~10.000 req/día en el plan gratuito).

## Seguridad

- **Anti-SSRF:** antes de seguir redirects, el servidor valida que cada URL apunte a un host público. Se rechazan `localhost`, dominios `.local`/`.internal`, IPs privadas literales (10/8, 127/8, 169.254/16, 172.16/12, 192.168/16, CGNAT, IPv6 ULA/link-local) y hostnames que resuelven a IPs privadas.
- **CORS:** configura `ALLOWED_ORIGIN` en producción; sin ella el endpoint acepta peticiones desde cualquier origen y terceros pueden consumir tus cuotas de API.
- **API keys:** la clave de Google Safe Browsing viaja en el header `x-goog-api-key` (no en la URL) para evitar exposición en logs.
- **Límites de entrada:** body máximo 50 KB, solo URLs `http(s)` de hasta 2000 caracteres.

## Limitaciones conocidas

- **Cuentas comprometidas:** si el atacante usa una cuenta legítima robada (ej. `usuario@empresa-real.com`), el dominio del remitente pasa todos los controles DNS. Detectarlo requiere acceso a las cabeceras DKIM/SPF completas del correo, que la herramienta no recibe.
- **Redirects via JavaScript:** el seguimiento de redirects HTTP solo detecta respuestas 3xx. Redirects implementados con JavaScript o meta-refresh no son detectados por el servidor (sí podrían serlo abriendo el enlace en un navegador con VirusTotal habilitado).
- **VirusTotal en lote:** el plan gratuito de VirusTotal permite ~4 consultas/minuto. Con muchas URLs en un correo, parte de las consultas a VT pueden fallar silenciosamente (las demás fuentes no se ven afectadas).
- **Coincidencia exacta en GSB:** los resultados de Google Safe Browsing se asocian por URL exacta; si Google canonicaliza la URL, la coincidencia puede no atribuirse a un salto concreto de la cadena.
- **Dominios de phishing nuevos:** un dominio registrado hace pocas horas puede no estar todavía en las bases de datos de URLhaus, ThreatFox, GSB o VirusTotal.
- **Falsos positivos:** patrones heurísticos en inglés pueden generar avisos (WARN) en correos legítimos de marketing. El score necesita superar 50/100 para marcar DANGER, lo que requiere múltiples señales simultáneas.
