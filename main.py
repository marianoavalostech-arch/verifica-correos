"""
Verificador de Phishing - Fase 1
Backend FastAPI con una sola fuente: Google Safe Browsing v4.

Flujo: el frontend envia una URL -> este backend la consulta contra
Google Safe Browsing -> devuelve un veredicto en JSON.

IMPORTANTE: la consulta a Google se hace desde el servidor, nunca desde
el navegador del usuario. Asi el navegador de quien usa la herramienta
nunca toca el sitio sospechoso.
"""

import os
import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuracion
# ---------------------------------------------------------------------------

# La API key se lee de una variable de entorno. NUNCA la escribas
# directamente en el codigo ni la subas a un repositorio publico.
GOOGLE_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Datos que identifican tu cliente ante Google (para sus logs).
# Pon aqui el nombre de tu proyecto cuando lo despliegues.
CLIENT_ID = "verificador-phishing"
CLIENT_VERSION = "0.1.0"

app = FastAPI(title="Verificador de Phishing", version="0.1.0")

# CORS: restringe los origenes permitidos al frontend real y a los
# entornos de desarrollo local habituales.
ALLOWED_ORIGINS = [
    "https://verifica-correos.netlify.app",
    "http://localhost:8888",   # Netlify Dev local
    "http://127.0.0.1:8888",
    "http://localhost:5500",   # Live Server / VS Code
    "http://127.0.0.1:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Modelos de datos (validacion automatica de FastAPI)
# ---------------------------------------------------------------------------

class CheckRequest(BaseModel):
    url: str


class CheckResponse(BaseModel):
    url: str
    verdict: str          # "safe" | "dangerous" | "unknown"
    threats: list[str]    # tipos de amenaza detectados por Google
    source: str           # de donde viene el veredicto
    note: str             # aviso obligatorio (lenguaje calificativo)


# ---------------------------------------------------------------------------
# Logica de consulta a Google Safe Browsing
# ---------------------------------------------------------------------------

async def query_safe_browsing(url: str) -> dict:
    """
    Consulta una URL contra las listas de Google Safe Browsing.
    Devuelve un dict con la lista de amenazas encontradas (vacia si esta limpia).
    """
    payload = {
        "client": {
            "clientId": CLIENT_ID,
            "clientVersion": CLIENT_VERSION,
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",      # esto cubre phishing
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    params = {"key": GOOGLE_API_KEY}

    # timeout para que una API lenta no cuelgue tu servidor
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(SAFE_BROWSING_URL, params=params, json=payload)
        resp.raise_for_status()
        data = resp.json()

    # Si Google no encuentra nada, devuelve un objeto vacio {}.
    # Si encuentra amenazas, devuelve {"matches": [...]}.
    matches = data.get("matches", [])
    threat_types = [m.get("threatType", "DESCONOCIDO") for m in matches]
    return {"threats": threat_types}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Endpoint simple para comprobar que el servidor esta vivo."""
    return {"status": "ok", "api_key_configured": bool(GOOGLE_API_KEY)}


@app.post("/check", response_model=CheckResponse)
async def check_url(req: CheckRequest):
    """
    Recibe una URL y devuelve un veredicto basado en Google Safe Browsing.
    """
    url = req.url.strip()

    # Aviso obligatorio: las advertencias deben usar lenguaje calificativo.
    note = (
        "Resultado orientativo. Ninguna herramienta detecta el 100% de las "
        "amenazas: un sitio puede ser peligroso aunque aparezca como limpio. "
        "Datos de Google Safe Browsing."
    )

    if not GOOGLE_API_KEY:
        return CheckResponse(
            url=url,
            verdict="unknown",
            threats=[],
            source="ninguna",
            note="Falta configurar la API key de Google Safe Browsing en el servidor.",
        )

    try:
        result = await query_safe_browsing(url)
    except httpx.HTTPError:
        return CheckResponse(
            url=url,
            verdict="unknown",
            threats=[],
            source="google_safe_browsing",
            note="No se pudo consultar Google Safe Browsing en este momento.",
        )

    threats = result["threats"]
    verdict = "dangerous" if threats else "safe"

    return CheckResponse(
        url=url,
        verdict=verdict,
        threats=threats,
        source="google_safe_browsing",
        note=note,
    )
