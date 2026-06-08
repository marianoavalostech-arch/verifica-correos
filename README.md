# Verifica Correos

Herramienta web para analizar correos electrónicos sospechosos. Detecta phishing, malware y señales de ingeniería social analizando el remitente, asunto, cuerpo y URLs del correo.

## Cómo funciona

El análisis se divide en cuatro dimensiones, cada una con un puntaje de 0 a 100. El banner principal muestra el **riesgo estimado** (el máximo entre las cuatro) con una barra de color.

### 1. Remitente

Análisis heurístico del dominio + consultas DNS en el navegador (sin backend):

| Señal | Fuente | Peso |
|---|---|---|
| TLD sospechoso | Lista interna | +35 |
| Typosquatting (ej. `gmai1.com`) | Distancia Levenshtein | +60 |
| Subdominios excesivos | Heurística | +20 |
| Mezcla números/letras | Heurística | +20 |
| Punycode / homógrafo | Heurística | +30 |
| Sin registros MX | Cloudflare DoH | +50 |
| Sin registro SPF | Cloudflare DoH | +20 |
| Sin política DMARC | Cloudflare DoH | +15 |
| Dominio < 30 días | RDAP (rdap.org) | +40 |
| Dominio < 180 días | RDAP (rdap.org) | +15 |

### 2. Asunto

Detecta urgencia, mayúsculas excesivas y exclamaciones.

### 3. Cuerpo

Reglas heurísticas para: urgencia, solicitud de credenciales, amenazas de suspensión, promesas de premios, presión para hacer clic, suplantación de marcas, reembolsos falsos y solicitudes de verificación.

### 4. URLs

Las URLs extraídas del cuerpo se verifican en paralelo contra cuatro fuentes:

| Fuente | Tipo | API key |
|---|---|---|
| **URLhaus** (abuse.ch) | URLs maliciosas activas | No |
| **ThreatFox** (abuse.ch) | IOCs: dominios C2, malware, phishing | No |
| **Google Safe Browsing** | Malware, phishing, software no deseado | Sí (`GOOGLE_SAFE_BROWSING_KEY`) |
| **VirusTotal** | +90 motores antivirus | Opcional (`VIRUSTOTAL_API_KEY`) |

También detecta acortadores de URL y plataformas de email tracking, decodificando el destino real cuando es posible.

## Fuentes externas (sin API key)

| Servicio | URL | Uso |
|---|---|---|
| Cloudflare DoH | `cloudflare-dns.com/dns-query` | Registros MX, SPF, DMARC |
| RDAP | `rdap.org/domain/<dominio>` | Antigüedad del dominio |
| URLhaus | `urlhaus-api.abuse.ch/v1/url/` | Detección de URLs maliciosas |
| ThreatFox | `threatfox-api.abuse.ch/api/v1/` | Detección de dominios maliciosos |

## Configuración en Netlify

Variables de entorno (Settings → Environment variables):

| Variable | Descripción | Requerida |
|---|---|---|
| `GOOGLE_SAFE_BROWSING_KEY` | Clave de Google Safe Browsing v4 | Recomendada |
| `VIRUSTOTAL_API_KEY` | Clave de VirusTotal v3 | Opcional |
| `ALLOWED_ORIGIN` | Dominio permitido en CORS (ej. `https://tu-sitio.netlify.app`) | Recomendada en producción |

Sin ninguna variable, la app funciona usando URLhaus, ThreatFox, Cloudflare DoH y RDAP.

## Estructura del proyecto

```
├── index.html                    # UI principal
├── app.css                       # Estilos
├── app.js                        # Lógica del cliente (análisis heurístico + DNS)
├── netlify/functions/
│   └── check.js                  # Función serverless (verifica URLs contra APIs)
├── netlify.toml                  # Configuración de Netlify (alias /check, rate limiting)
└── .env.example                  # Variables de entorno de ejemplo
```

## Rate limiting

La función serverless tiene un límite de **20 requests por minuto por IP**, configurado en `netlify.toml`. Esto protege la cuota diaria de Google Safe Browsing (~10.000 req/día en el plan gratuito).
