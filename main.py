"""
Verificador de Phishing — backend FastAPI local
Fuentes (consultadas en paralelo):
  1. URLhaus / abuse.ch  — libre, sin clave
  2. Google Safe Browsing v4 — requiere GOOGLE_SAFE_BROWSING_KEY
  3. VirusTotal v3            — requiere VIRUSTOTAL_API_KEY (opcional)

NUNCA el navegador del usuario toca el sitio sospechoso.
"""

import asyncio
import base64
import os

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─────────────────────────────────────────────────────────────────
# Configuración
# ─────────────────────────────────────────────────────────────────

GOOGLE_API_KEY     = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

GSB_ENDPOINT       = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_URL        = "https://urlhaus-api.abuse.ch/v1/url/"
VIRUSTOTAL_BASE    = "https://www.virustotal.com/api/v3/urls"

CLIENT_ID          = "verificador-phishing"
CLIENT_VERSION     = "0.2.0"

app = FastAPI(title="Verificador de Phishing", version="0.2.0")

ALLOWED_ORIGINS = [
    "https://verifica-correos.netlify.app",
    "http://localhost:8888",
    "http://127.0.0.1:8888",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────
# Modelos
# ─────────────────────────────────────────────────────────────────

class CheckRequest(BaseModel):
    url:  str | None = None          # una sola URL
    urls: list[str] | None = None    # varias URLs (desde el cuerpo del email)


class UrlResult(BaseModel):
    url:     str
    verdict: str        # "safe" | "dangerous"
    threats: list[str]


class CheckResponse(BaseModel):
    verdict: str        # veredicto global
    results: list[UrlResult]
    source:  str
    note:    str


# ─────────────────────────────────────────────────────────────────
# Funciones de consulta por fuente
# ─────────────────────────────────────────────────────────────────

async def query_gsb(urls: list[str]) -> dict[str, list[str]]:
    """Google Safe Browsing v4 (batch) → {url: [threatType, …]}."""
    if not GOOGLE_API_KEY:
        return {}
    payload = {
        "client": {"clientId": CLIENT_ID, "clientVersion": CLIENT_VERSION},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": u} for u in urls],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                GSB_ENDPOINT, params={"key": GOOGLE_API_KEY}, json=payload
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return {}

    hits: dict[str, list[str]] = {}
    for m in data.get("matches", []):
        u = m.get("threat", {}).get("url", "")
        hits.setdefault(u, []).append(m.get("threatType", "UNKNOWN"))
    return hits


async def query_urlhaus(url: str) -> list[str]:
    """URLhaus (abuse.ch) — base de datos abierta, sin clave."""
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                URLHAUS_URL,
                data={"url": url},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return []

    if (data.get("query_status") or "no_results") == "no_results":
        return []

    raw = (data.get("threat") or "malware").lower()
    mapping = {
        "malware_download": "URLHAUS_MALWARE",
        "botnet_cc":        "URLHAUS_BOTNET",
        "phishing":         "URLHAUS_PHISHING",
    }
    return [mapping.get(raw, "URLHAUS_MALWARE")]


async def query_virustotal(url: str) -> list[str]:
    """VirusTotal v3 — requiere VIRUSTOTAL_API_KEY."""
    if not VIRUSTOTAL_API_KEY:
        return []
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.get(
                f"{VIRUSTOTAL_BASE}/{url_id}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
            )
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return []

    stats      = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious  >= 2: return ["VIRUSTOTAL_MALICIOSO"]
    if suspicious >= 3: return ["VIRUSTOTAL_SOSPECHOSO"]
    return []


# ─────────────────────────────────────────────────────────────────
# Verificación combinada por URL
# ─────────────────────────────────────────────────────────────────

async def check_single(url: str, gsb_hits: dict[str, list[str]]) -> UrlResult:
    """Combina resultados de URLhaus + VirusTotal + GSB para una URL."""
    uh_threats, vt_threats = await asyncio.gather(
        query_urlhaus(url),
        query_virustotal(url),
    )
    threats = [*gsb_hits.get(url, []), *uh_threats, *vt_threats]
    return UrlResult(
        url=url,
        verdict="dangerous" if threats else "safe",
        threats=threats,
    )


# ─────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "sources": {
            "google_safe_browsing": bool(GOOGLE_API_KEY),
            "urlhaus":              True,
            "virustotal":           bool(VIRUSTOTAL_API_KEY),
        },
    }


@app.post("/check", response_model=CheckResponse)
async def check(req: CheckRequest):
    # Normalizar y deduplicar URLs
    urls: list[str] = []
    if req.url:
        urls.append(req.url.strip())
    if req.urls:
        urls.extend(u.strip() for u in req.urls if u.strip())
    urls = list(dict.fromkeys(urls))

    if not urls:
        return CheckResponse(
            verdict="unknown", results=[], source="ninguna",
            note="No se proporcionó ninguna URL.",
        )

    # Fuentes activas
    active_sources = ["URLhaus"]
    if GOOGLE_API_KEY:
        active_sources.insert(0, "Google Safe Browsing")
    if VIRUSTOTAL_API_KEY:
        active_sources.append("VirusTotal")

    # GSB en batch + URLhaus/VT en paralelo por URL
    gsb_hits = await query_gsb(urls)
    results  = await asyncio.gather(*[check_single(u, gsb_hits) for u in urls])

    any_dangerous = any(r.verdict == "dangerous" for r in results)
    source_str    = " + ".join(active_sources)

    note = (
        f"Resultado orientativo. Fuentes consultadas: {source_str}. "
        "Ninguna herramienta detecta el 100 % de las amenazas: "
        "un correo puede ser peligroso aunque aparezca como limpio."
    )

    return CheckResponse(
        verdict="dangerous" if any_dangerous else "safe",
        results=list(results),
        source=source_str,
        note=note,
    )
