// ═══════════════════════════════════════════════════════
//  file-worker.js
//  Análisis local de archivos adjuntos (sandbox: Web Worker)
//
//  - Nunca ejecuta el archivo, solo lee bytes.
//  - Nunca sube nada a internet.
//  - No usa eval/Function ni interpreta el contenido como código.
//  - Reporta progreso paso a paso vía postMessage para la checklist.
// ═══════════════════════════════════════════════════════

const MAX_BYTES        = 25 * 1024 * 1024; // 25 MB
const MAX_ZIP_ENTRIES  = 2000;
const MAX_SCAN_BYTES   = 6 * 1024 * 1024;  // tope para escaneo de texto (PDF/strings)
const ZIP_BOMB_RATIO   = 150;              // descomprimido / comprimido

function step(id, status, detail) {
  postMessage({ type: "step", id, status, detail });
}

function bytesToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function fmtSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / (1024 * 1024)).toFixed(2) + " MB";
}

// ── Firmas binarias (magic bytes) ──────────────────────
const SIGNATURES = [
  { hex: "25504446",                 family: "pdf",     label: "PDF" },
  { hex: "4d5a",                     family: "exe",     label: "Ejecutable Windows (EXE/DLL)" },
  { hex: "7f454c46",                 family: "elf",     label: "Ejecutable Linux (ELF)" },
  { hex: "cafebabe",                 family: "macho",   label: "Ejecutable Mach-O / Java class" },
  { hex: "d0cf11e0a1b11ae1",         family: "ole",     label: "Documento OLE compuesto (Office 97-2003)" },
  { hex: "504b0304",                 family: "zip",     label: "ZIP / formato basado en ZIP" },
  { hex: "504b0506",                 family: "zip",     label: "ZIP (vacío)" },
  { hex: "504b0708",                 family: "zip",     label: "ZIP (spanned)" },
  { hex: "526172211a0700",           family: "rar",     label: "RAR" },
  { hex: "377abcaf271c",             family: "7z",      label: "7-Zip" },
  { hex: "1f8b08",                   family: "gzip",    label: "GZIP" },
  { hex: "ffd8ff",                   family: "image",   label: "Imagen JPEG" },
  { hex: "89504e470d0a1a0a",         family: "image",   label: "Imagen PNG" },
  { hex: "474946383761",             family: "image",   label: "Imagen GIF" },
  { hex: "474946383961",             family: "image",   label: "Imagen GIF" },
  { hex: "25215053",                 family: "ps",      label: "PostScript" },
  { hex: "7b5c72746631",             family: "rtf",     label: "Documento RTF" },
];

const EXT_FAMILIES = {
  pdf:  "pdf",
  exe: "exe", dll: "exe", msi: "ole",
  doc: "ole", xls: "ole", ppt: "ole",
  docx: "zip", xlsx: "zip", pptx: "zip", docm: "zip", xlsm: "zip", pptm: "zip",
  zip: "zip", jar: "zip", apk: "zip", odt: "zip", ods: "zip", odp: "zip",
  rar: "rar", "7z": "7z", gz: "gzip",
  jpg: "image", jpeg: "image", png: "image", gif: "image",
  rtf: "rtf",
  txt: "text", csv: "text", html: "text", htm: "text", xml: "text", json: "text",
};

function detectMagic(bytes) {
  const hex16 = bytesToHex(bytes.slice(0, 16).buffer);
  for (const sig of SIGNATURES) {
    if (hex16.startsWith(sig.hex)) return sig;
  }
  // Texto plano: heurística simple — sin bytes nulos en los primeros 1024
  const sample = bytes.slice(0, 1024);
  let printable = 0;
  for (const b of sample) {
    if (b === 0) return { hex: "", family: "binary", label: "Binario desconocido" };
    if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13 || b >= 128) printable++;
  }
  if (sample.length === 0 || printable / sample.length > 0.85) {
    return { hex: "", family: "text", label: "Texto plano" };
  }
  return { hex: "", family: "binary", label: "Binario desconocido" };
}

// ── Parser ZIP ──────────────────────────────────────────
// Estrategia principal: leer el CENTRAL DIRECTORY (vía EOCD). A diferencia
// de las cabeceras locales, el central directory siempre contiene los
// tamaños reales — los ZIP con "data descriptors" (flag bit 3) dejan los
// tamaños locales en 0, lo que permitía evadir la detección de zip bombs
// y marcaba como "truncados" archivos válidos.
// Fallback: recorrido de cabeceras locales (ZIPs corruptos/sin EOCD).

function parseZipCentralDirectory(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // Buscar EOCD (PK\x05\x06) desde el final; el comentario puede ocupar
  // hasta 64 KB, así que se escanean los últimos 64 KB + 22 bytes.
  const minEocd = 22;
  if (bytes.length < minEocd) return null;
  const scanStart = Math.max(0, bytes.length - 65536 - minEocd);
  let eocd = -1;
  for (let i = bytes.length - minEocd; i >= scanStart; i--) {
    if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd === -1) return null;

  const totalEntries = view.getUint16(eocd + 10, true);
  const cdOffset     = view.getUint32(eocd + 16, true);
  // ZIP64 (offset/count saturados) → no soportado aquí, usar fallback
  if (cdOffset === 0xffffffff || totalEntries === 0xffff) return null;
  if (cdOffset >= bytes.length) return null;

  const entries = [];
  let totalCompressed = 0;
  let totalUncompressed = 0;
  let truncated = false;
  let offset = cdOffset;

  while (entries.length < totalEntries && offset + 46 <= bytes.length) {
    if (view.getUint32(offset, true) !== 0x02014b50) break; // PK\x01\x02
    if (entries.length >= MAX_ZIP_ENTRIES) { truncated = true; break; }
    const compSize   = view.getUint32(offset + 20, true);
    const uncompSize = view.getUint32(offset + 24, true);
    const nameLen    = view.getUint16(offset + 28, true);
    const extraLen   = view.getUint16(offset + 30, true);
    const commentLen = view.getUint16(offset + 32, true);
    const nameBytes  = bytes.slice(offset + 46, offset + 46 + nameLen);
    const name       = new TextDecoder("utf-8", { fatal: false }).decode(nameBytes);

    entries.push({ name, compSize, uncompSize });
    totalCompressed   += compSize;
    totalUncompressed += uncompSize;
    offset += 46 + nameLen + extraLen + commentLen;
  }

  if (entries.length === 0) return null;
  if (entries.length < totalEntries && !truncated) truncated = true;
  return { entries, totalCompressed, totalUncompressed, truncated };
}

function parseZip(bytes) {
  const central = parseZipCentralDirectory(bytes);
  if (central) return central;
  return parseZipLocalHeaders(bytes);
}

// ── Fallback: cabeceras locales ─────────────────────────
function parseZipLocalHeaders(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const entries = [];
  let offset = 0;
  let totalCompressed = 0;
  let totalUncompressed = 0;
  let truncated = false;

  while (offset + 30 <= bytes.length && entries.length < MAX_ZIP_ENTRIES) {
    if (view.getUint32(offset, true) !== 0x04034b50) break; // "PK\x03\x04"
    const flags          = view.getUint16(offset + 6, true);
    const compSize       = view.getUint32(offset + 18, true);
    const uncompSize     = view.getUint32(offset + 22, true);
    const nameLen        = view.getUint16(offset + 26, true);
    const extraLen       = view.getUint16(offset + 28, true);
    const nameBytes      = bytes.slice(offset + 30, offset + 30 + nameLen);
    const name           = new TextDecoder("utf-8", { fatal: false }).decode(nameBytes);

    entries.push({ name, compSize, uncompSize });
    totalCompressed   += compSize;
    totalUncompressed += uncompSize;

    const dataDescriptor = (flags & 0x0008) !== 0; // tamaños reales van después de los datos
    if (dataDescriptor || (compSize === 0 && uncompSize === 0 && !name.endsWith("/"))) {
      // Buscar la siguiente firma local/central conocida desde aquí
      const searchFrom = offset + 30 + nameLen + extraLen;
      const next = findNextSignature(view, searchFrom);
      if (next === -1) { truncated = true; break; }
      offset = next;
      continue;
    }

    offset = offset + 30 + nameLen + extraLen + compSize;
  }

  if (offset + 30 <= bytes.length && view.getUint32(offset, true) === 0x04034b50 && entries.length >= MAX_ZIP_ENTRIES) {
    truncated = true;
  }

  return { entries, totalCompressed, totalUncompressed, truncated };
}

function findNextSignature(view, from) {
  // Busca PK\x03\x04 (local) o PK\x01\x02 (central directory) o PK\x05\x06 (end)
  for (let i = from; i + 4 <= view.byteLength; i++) {
    const sig = view.getUint32(i, true);
    if (sig === 0x04034b50 || sig === 0x02014b50 || sig === 0x06054b50) return sig === 0x04034b50 ? i : -1;
  }
  return -1;
}

// ── Análisis principal ──────────────────────────────────
async function analyze(file) {
  const issues = [];   // { level: 'warn'|'danger', text }
  const meta = { name: file.name, size: file.size, declaredType: file.type || "(desconocido)" };

  // Paso 1: lectura en memoria
  let buf;
  try {
    buf = await file.arrayBuffer();
  } catch (e) {
    step("read", "danger", "No se pudo leer el archivo: " + e.message);
    postMessage({ type: "result", report: { meta, issues: [{ level: "danger", text: "Error de lectura." }], aborted: true } });
    return;
  }
  const bytes = new Uint8Array(buf);
  step("read", "ok", `${fmtSize(bytes.length)} cargados en memoria (no se escribió a disco)`);

  // Paso 2: tamaño
  if (bytes.length > MAX_BYTES) {
    step("size", "danger", `${fmtSize(bytes.length)} supera el límite de ${fmtSize(MAX_BYTES)}`);
    postMessage({ type: "result", report: { meta, issues: [{ level: "danger", text: `Archivo demasiado grande (${fmtSize(bytes.length)}). Análisis abortado por seguridad.` }], aborted: true } });
    return;
  }
  step("size", "ok", `${fmtSize(bytes.length)} (dentro del límite de ${fmtSize(MAX_BYTES)})`);

  // Paso 3: hash SHA-256
  let sha256 = "(no disponible)";
  try {
    const digest = await crypto.subtle.digest("SHA-256", buf);
    sha256 = bytesToHex(digest);
    step("hash", "ok", sha256);
  } catch (e) {
    step("hash", "warn", "No se pudo calcular el hash");
  }
  meta.sha256 = sha256;

  // Paso 4: magic bytes
  const magic = detectMagic(bytes);
  meta.detectedType = magic.label;
  meta.detectedFamily = magic.family;
  step("magic", "ok", magic.label + (magic.hex ? ` (firma: ${bytesToHex(bytes.slice(0, magic.hex.length / 2).buffer)})` : ""));

  // Paso 5: extensión vs tipo real + detección de doble extensión
  const ext = (file.name.split(".").pop() || "").toLowerCase();
  const expectedFamily = EXT_FAMILIES[ext];
  meta.extension = ext || "(sin extensión)";

  let extStatus = "ok";
  let extDetail = "El tipo real coincide con lo esperado para esta extensión";

  if (magic.family === "exe" || magic.family === "elf" || magic.family === "macho") {
    issues.push({ level: "danger", text: `El contenido real es un EJECUTABLE (${magic.label}), independientemente de su extensión ".${ext || "?"}". Riesgo muy alto: no lo abras.` });
    extStatus = "danger";
    extDetail = "Ejecutable disfrazado o archivo .exe/.dll directo";
  } else if (expectedFamily && magic.family !== "binary" && magic.family !== expectedFamily &&
             !(expectedFamily === "text" && magic.family === "text")) {
    issues.push({ level: "warn", text: `La extensión ".${ext}" sugiere "${expectedFamily}", pero el contenido real es "${magic.label}". Posible intento de disfrazar el archivo.` });
    extStatus = "warn";
    extDetail = `.${ext} → se esperaba ${expectedFamily}, se detectó ${magic.family}`;
  }

  // Detectar doble extensión en el nombre del archivo (ej: "factura.pdf.exe")
  // Técnica habitual para disfrazar ejecutables como documentos de apariencia inocua.
  const SAFE_LIKE_EXTS = new Set(["pdf","doc","docx","xls","xlsx","ppt","pptx",
                                   "jpg","jpeg","png","gif","txt","zip","rar"]);
  const nameParts = file.name.split(".");
  if (nameParts.length > 2) {
    const secondToLast = nameParts[nameParts.length - 2].toLowerCase();
    if (SAFE_LIKE_EXTS.has(secondToLast)) {
      issues.push({ level: "warn", text: `El nombre del archivo usa doble extensión: ".${secondToLast}.${ext}" — técnica habitual para disfrazar ejecutables o scripts como documentos.` });
      if (extStatus === "ok") {
        extStatus = "warn";
        extDetail  = `Doble extensión detectada: .${secondToLast}.${ext}`;
      } else {
        extDetail += ` · doble extensión: .${secondToLast}.${ext}`;
      }
    }
  }

  step("extmatch", extStatus, extDetail);

  // Paso 6: estructura interna
  let structureDetail = "No aplica para este tipo de archivo";
  let zipInfo = null;

  if (magic.family === "zip") {
    zipInfo = parseZip(bytes);
    const names = zipInfo.entries.map(e => e.name);
    let kind = "ZIP genérico";
    if (names.includes("[Content_Types].xml")) {
      if (names.some(n => n.startsWith("word/"))) kind = "Documento Word (OOXML)";
      else if (names.some(n => n.startsWith("xl/"))) kind = "Hoja de cálculo Excel (OOXML)";
      else if (names.some(n => n.startsWith("ppt/"))) kind = "Presentación PowerPoint (OOXML)";
      else kind = "Documento Office (OOXML)";
    } else if (names.includes("AndroidManifest.xml")) {
      kind = "Paquete Android (APK)";
    } else if (names.some(n => n === "META-INF/MANIFEST.MF")) {
      kind = "Archivo Java (JAR)";
    }
    meta.zipKind = kind;
    structureDetail = `${kind} — ${zipInfo.entries.length}${zipInfo.truncated ? "+" : ""} elementos internos`;

    // Zip bomb heurístico
    if (zipInfo.totalCompressed > 0) {
      const ratio = zipInfo.totalUncompressed / zipInfo.totalCompressed;
      if (ratio > ZIP_BOMB_RATIO && zipInfo.totalUncompressed > 50 * 1024 * 1024) {
        issues.push({ level: "danger", text: `Posible "zip bomb": ${fmtSize(zipInfo.totalCompressed)} comprimidos se expandirían a ${fmtSize(zipInfo.totalUncompressed)} (ratio ${ratio.toFixed(0)}x). No descomprimir.` });
        structureDetail += ` · ratio de compresión ${ratio.toFixed(0)}x (sospechoso)`;
      }
    }
    // Doble extensión / ejecutables dentro del zip
    const suspiciousInner = names.filter(n => /\.(exe|scr|bat|cmd|js|vbs|ps1|jar|com|pif|hta)$/i.test(n));
    if (suspiciousInner.length) {
      issues.push({ level: "warn", text: `El archivo comprimido contiene elementos ejecutables/script: ${suspiciousInner.slice(0, 5).join(", ")}${suspiciousInner.length > 5 ? "…" : ""}` });
    }
  } else if (magic.family === "pdf") {
    structureDetail = "PDF: se buscarán JavaScript, autoarranque y adjuntos";
  } else if (magic.family === "ole") {
    structureDetail = "Documento OLE compuesto (formato Office 97-2003) — estructura interna no inspeccionable por completo en el navegador";
    issues.push({ level: "warn", text: "Formato Office antiguo (.doc/.xls/.ppt). Puede contener macros VBA que no es posible auditar completamente en el navegador. Tratar con precaución, especialmente si pide \"Habilitar contenido\"." });
  }
  step("structure", zipInfo?.truncated ? "warn" : "ok", structureDetail + (zipInfo?.truncated ? " (lista truncada por límite de seguridad)" : ""));

  // Paso 7: macros / scripts embebidos
  let macroDetail = "Sin indicios de macros o scripts embebidos";
  let macroLevel = "ok";

  if (zipInfo) {
    const names = zipInfo.entries.map(e => e.name.toLowerCase());
    if (names.some(n => n.includes("vbaproject.bin") || n.startsWith("macros/") || n.includes("vbaproject"))) {
      issues.push({ level: "danger", text: "El documento contiene macros VBA (vbaProject.bin). Las macros pueden ejecutar código arbitrario al abrir el archivo si se habilitan. No habilites \"Editar\"/\"Habilitar contenido\" salvo que confíes plenamente en el origen." });
      macroDetail = "Macros VBA detectadas (vbaProject.bin)";
      macroLevel = "danger";
    }
    if (names.some(n => n.endsWith(".dll") || n.endsWith(".exe"))) {
      issues.push({ level: "danger", text: "El archivo comprimido contiene un ejecutable (.exe/.dll) embebido." });
      macroDetail += " · ejecutable embebido en el paquete";
      macroLevel = "danger";
    }
  } else if (magic.family === "pdf") {
    // Escanear como latin1 (1 byte = 1 char) para buscar tokens PDF típicos
    const scanLen = Math.min(bytes.length, MAX_SCAN_BYTES);
    let text = "";
    const chunk = 65536;
    for (let i = 0; i < scanLen; i += chunk) {
      text += String.fromCharCode(...bytes.subarray(i, Math.min(i + chunk, scanLen)));
    }
    const findings = [];
    if (/\/JavaScript/.test(text) || /\/JS\b/.test(text)) findings.push("/JavaScript embebido");
    if (/\/OpenAction/.test(text)) findings.push("/OpenAction (ejecución automática al abrir)");
    if (/\/Launch/.test(text)) findings.push("/Launch (puede lanzar programas externos)");
    if (/\/EmbeddedFile/.test(text)) findings.push("/EmbeddedFile (archivos adjuntos ocultos)");
    if (/\/AA\b/.test(text)) findings.push("/AA (acciones automáticas)");
    if (/\/RichMedia/.test(text)) findings.push("/RichMedia (contenido Flash/multimedia embebido)");

    if (findings.length) {
      const hasDangerous = findings.some(f => /OpenAction|Launch|JavaScript/.test(f));
      issues.push({ level: hasDangerous ? "danger" : "warn", text: `El PDF contiene elementos activos: ${findings.join(", ")}.` });
      macroDetail = findings.join(", ");
      macroLevel = hasDangerous ? "danger" : "warn";
    }
  }
  step("macros", macroLevel, macroDetail);

  // Paso 8: informe final
  let overall = "ok";
  if (issues.some(i => i.level === "danger")) overall = "danger";
  else if (issues.some(i => i.level === "warn")) overall = "warn";
  step("report", "ok", "Informe generado");

  postMessage({ type: "result", report: { meta, issues, overall } });
}

self.onmessage = (e) => {
  const { file } = e.data;
  analyze(file).catch(err => {
    postMessage({ type: "result", report: { meta: { name: file?.name }, issues: [{ level: "danger", text: "Error inesperado durante el análisis: " + err.message }], overall: "danger", aborted: true } });
  });
};
