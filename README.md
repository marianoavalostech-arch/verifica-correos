# Verifica Correos

Herramienta gratuita y open source para detectar phishing, remitentes falsos y URLs maliciosas en correos electrónicos.

[![Deploy to Netlify](https://www.netlify.com/img/deploy/button.svg)](https://app.netlify.com/start/deploy?repository=https://github.com/profemarianoavalos/verifica-correos)

---

## Qué hace

| Modo | Qué analiza |
|---|---|
| 🔗 **URL** | Verifica un enlace contra Google Safe Browsing |
| 📄 **Cuerpo** | Extrae todos los enlaces del texto pegado y los verifica en lote |
| ✉ **Remitente** | Analiza la dirección del remitente: formato, MX por DNS, typosquatting, TLD sospechoso |

La consulta a Google Safe Browsing se realiza **desde el servidor** (función serverless de Netlify), nunca desde el navegador del usuario.

---

## Estructura del proyecto

```
verifica-correos/
├── index.html                  ← Frontend (todo en un archivo)
├── netlify.toml                ← Config de Netlify + redirect /check
├── package.json
├── netlify/
│   └── functions/
│       └── check.js            ← Función serverless (reemplaza al backend Python)
├── main.py                     ← Backend alternativo en Python / FastAPI
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## Despliegue en Netlify (recomendado)

### 1. Obtener la API key de Google Safe Browsing

1. Abre [Google Cloud Console](https://console.cloud.google.com/).
2. Crea un proyecto nuevo.
3. Busca **"Safe Browsing API"** y habilítala.
4. Ve a **APIs y servicios → Credenciales → Crear credenciales → Clave de API**.
5. Copia la clave. La API es **gratuita** para uso no comercial.

### 2. Subir el proyecto a GitHub

```bash
git init
git add .
git commit -m "feat: versión inicial"
git remote add origin https://github.com/TU_USUARIO/verifica-correos.git
git push -u origin main
```

### 3. Conectar con Netlify

1. Entra en [netlify.com](https://netlify.com) y haz clic en **"Add new site → Import an existing project"**.
2. Selecciona tu repositorio de GitHub.
3. La configuración de build se lee automáticamente de `netlify.toml`.
4. Ve a **Site configuration → Environment variables** y añade:
   ```
   GOOGLE_SAFE_BROWSING_KEY = tu_clave_aquí
   ```
5. Haz clic en **"Deploy site"**.

O usa el botón de despliegue rápido de arriba.

---

## Desarrollo local

### Opción A — Con Netlify CLI (recomendado, simula el entorno real)

```bash
npm install
cp .env.example .env
# Edita .env y añade tu clave

npm run dev    # inicia Netlify Dev en http://localhost:8888
```

### Opción B — Con el backend Python / FastAPI

```bash
cd .
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt

export GOOGLE_SAFE_BROWSING_KEY="tu_clave"
uvicorn main:app --reload --port 8000
```

Abre `index.html` en el navegador. Para desarrollo local con Python, cambia en `index.html` la línea:
```js
const CHECK_ENDPOINT = "/check";
```
por:
```js
const CHECK_ENDPOINT = "http://127.0.0.1:8000";
```

---

## URLs de prueba oficiales de Google

Google proporciona URLs que siempre deben dar positivo (para tests):

- `http://malware.testing.google.test/testing/malware/`
- `http://testsafebrowsing.appspot.com/s/phishing.html`

Cualquier sitio normal (p. ej. `https://www.wikipedia.org`) debe dar "sin amenazas".

---

## Notas de seguridad

- La API key vive en variables de entorno, **nunca en el código**.
- El `.env` real está en `.gitignore` y no se sube al repositorio.
- Los avisos usan lenguaje calificativo ("posiblemente peligroso") como exigen los términos de Google.
- La función serverless tiene timeout de 10 s para evitar bloqueos.
- Las cabeceras de seguridad HTTP se configuran en `netlify.toml`.

---

## Hoja de ruta

- [x] Fase 1 — Verificación de URL con Google Safe Browsing
- [x] Fase 2 — Análisis del remitente (MX, typosquatting, TLD)
- [x] Fase 3 — Análisis del cuerpo del correo (extracción de URLs en lote)
- [ ] Fase 4 — Verificación adicional con VirusTotal / URLhaus
- [ ] Fase 5 — Puntuación ponderada 0–100
- [ ] Fase 6 — Seguimiento de redirecciones

---

## Licencia

MIT — úsalo, modifícalo y compártelo libremente.
