from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import json
import zipfile
import io
import os
import httpx
from pathlib import Path
from typing import List

from analyzer import (
    extract_endpoints_from_java_code,
    extract_endpoints_from_text,
    parse_nsc_xml,
    detect_anomalies,
    classify_environment,
    correlate_endpoints_with_nsc,
    analyze_endpoint_tls_per_endpoint,
)
from decompiler import APKDecompiler

# Charger les variables d'environnement depuis .env
from pathlib import Path
env_path = Path(__file__).parent / ".env"
if env_path.exists():
    try:
        with open(env_path, 'r', encoding='utf-8-sig') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()
    except Exception:
        pass  # Si erreur, utiliser la variable d'environnement existante

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

app = FastAPI(title="TLS Posture Analyzer API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "api_key_set": bool(GROQ_API_KEY)}


@app.post("/config/api-key")
async def set_api_key(api_key: str = Form(...)):
    """
    Configure la clé API Groq via l'API (au lieu de taper dans le terminal).
    Met à jour les variables globales et le fichier .env.
    """
    global GROQ_API_KEY
    
    if not api_key or len(api_key) < 10:
        raise HTTPException(status_code=400, detail="Clé API invalide")
    
    GROQ_API_KEY = api_key
    os.environ["GROQ_API_KEY"] = api_key
    
    # Mise à jour du fichier .env
    try:
        env_path = Path(__file__).parent / ".env"
        env_content = f"# 🔑 Clé API Groq (pour les analyses IA)\n# Obtenez votre clé sur https://console.groq.com\nGROQ_API_KEY={api_key}\n"
        env_path.write_text(env_content)
    except Exception as e:
        return {"status": "warning", "message": f"Clé configurée en mémoire mais erreur fichier: {str(e)}"}
    
    return {"status": "success", "message": "Clé API Groq configurée avec succès"}


@app.get("/config/api-key-status")
def api_key_status():
    """
    Vérifiez le statut de la clé API Groq sans exposer la clé entière.
    """
    if not GROQ_API_KEY:
        return {"configured": False, "message": "Clé API non configurée"}
    
    # Afficher seulement les premiers et derniers caractères pour la sécurité
    masked = f"{GROQ_API_KEY[:7]}...{GROQ_API_KEY[-5:]}"
    return {"configured": True, "api_key_preview": masked, "length": len(GROQ_API_KEY)}


@app.post("/analyze/text")
async def analyze_text(
    apk_text:   str = Form(default=""),
    proxy_text: str = Form(default=""),
    nsc_xml:    str = Form(default=""),
):
    from analyzer import extract_endpoints_from_text
    all_text = "\n".join([apk_text, proxy_text])
    endpoints = extract_endpoints_from_text(all_text)
    for ep in endpoints:
        ep["env"] = classify_environment(ep["value"])
    anomalies = detect_anomalies(endpoints)
    tls_checks = parse_nsc_xml(nsc_xml) if nsc_xml.strip() else []
    endpoint_tls_analysis = analyze_endpoint_tls_per_endpoint(endpoints, nsc_xml)
    endpoint_coverage = correlate_endpoints_with_nsc(endpoints, nsc_xml) if nsc_xml.strip() else []
    # Merge TLS analysis results into endpoint objects where possible
    tls_map = {item["endpoint"]: item for item in endpoint_tls_analysis}
    for ep in endpoints:
        if ep["value"] in tls_map:
            ep["tls_info"] = tls_map[ep["value"]]
    return {
        "endpoints": endpoints,
        "endpoint_tls_analysis": endpoint_tls_analysis,
        "endpoint_coverage": endpoint_coverage,
        "anomalies": anomalies,
        "tls_checks": tls_checks,
        "stats": {
            "total":     len(endpoints),
            "prod":      sum(1 for e in endpoints if e["env"] == "prod"),
            "test":      sum(1 for e in endpoints if e["env"] == "test"),
            "cleartext": sum(1 for e in endpoints if e["value"].startswith("http://")),
            "critical":  sum(1 for a in anomalies if a["severity"] == "critical"),
            "high":      sum(1 for a in anomalies if a["severity"] == "high"),
        }
    }


@app.post("/analyze/apk")
async def analyze_apk(file: UploadFile = File(...)):
    """
    Analyse complète d'APK avec DÉCOMPILATION comme flux principal.
    - Extrait le NSC via zipfile (rapide)
    - Décompile avec apktool + jadx (analyse profonde)
    - Analyse le code Java décompilé (endpoints précis)
    """
    content = await file.read()
    decompiler = APKDecompiler()
    
    # 1️⃣ EXTRACTION RAPIDE du NSC et des chaînes brutes utiles pour les vérifications TLS
    nsc_xml = ""
    raw_parts = []

    # ── Décodeur AXML (Android Binary XML) pur Python ─────────────────────────
    # Les fichiers .xml dans un APK sont compilés en binaire AXML, pas du XML texte.
    # Ce décodeur lit le format AXML et reconstruit le XML lisible.
    def decode_axml(data: bytes) -> str:
        """
        Décode un Android Binary XML (AXML) en XML texte lisible.
        Format : magic 0x00080003, suivi de chunks STRING_POOL + XML_START_ELEMENT, etc.
        Implémentation minimale mais suffisante pour NSC et AndroidManifest.
        """
        import struct

        MAGIC       = 0x00080003
        RES_STRING  = 0x001C0001
        RES_START   = 0x00100102
        RES_END     = 0x00100103
        RES_ATTR    = 0x00100104  # non utilisé mais réservé

        if len(data) < 8:
            return ""
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic != MAGIC:
            # Pas du AXML → peut-être déjà du XML texte (APK debug non compilé)
            text = data.decode("utf-8", errors="replace")
            if "<" in text and ">" in text:
                return text
            return ""

        # Lire la string pool
        strings = []
        offset = 8  # skip file header
        while offset + 8 <= len(data):
            chunk_type, chunk_size = struct.unpack_from("<II", data, offset)[:2]
            if chunk_size == 0:
                break
            if chunk_type == RES_STRING:
                try:
                    str_count = struct.unpack_from("<I", data, offset + 8)[0]
                    style_count = struct.unpack_from("<I", data, offset + 12)[0]
                    flags = struct.unpack_from("<I", data, offset + 16)[0]
                    str_start = struct.unpack_from("<I", data, offset + 20)[0]
                    offsets_base = offset + 28
                    pool_base = offset + 28 + str_count * 4 + style_count * 4

                    is_utf8 = bool(flags & (1 << 8))
                    for i in range(str_count):
                        str_off = struct.unpack_from("<I", data, offsets_base + i * 4)[0]
                        pos = pool_base + str_off
                        try:
                            if is_utf8:
                                # UTF-8: premier octet = longueur UTF-16, deuxième = longueur UTF-8
                                u16_len = data[pos] if data[pos] < 0x80 else ((data[pos] & 0x7F) << 8) | data[pos + 1]
                                skip = 1 if data[pos] < 0x80 else 2
                                pos += skip
                                u8_len = data[pos] if data[pos] < 0x80 else ((data[pos] & 0x7F) << 8) | data[pos + 1]
                                skip2 = 1 if data[pos] < 0x80 else 2
                                pos += skip2
                                strings.append(data[pos:pos + u8_len].decode("utf-8", errors="replace"))
                            else:
                                # UTF-16LE: premier word = longueur
                                slen = struct.unpack_from("<H", data, pos)[0]
                                pos += 2
                                raw = data[pos:pos + slen * 2]
                                strings.append(raw.decode("utf-16-le", errors="replace"))
                        except Exception:
                            strings.append("")
                except Exception:
                    pass
            offset += chunk_size

        # Lire les éléments XML
        lines = ['<?xml version="1.0" encoding="utf-8"?>']
        stack = []
        offset = 8
        ns_map = {}  # prefix → uri

        ANDROID_NS = "http://schemas.android.com/apk/res/android"
        ns_prefix = "android"

        while offset + 8 <= len(data):
            chunk_type, chunk_size = struct.unpack_from("<II", data, offset)[:2]
            if chunk_size == 0:
                break

            if chunk_type == RES_START:
                try:
                    # ns(4) name(4) attr_start(2) attr_size(2) attr_count(2) id(2) cls(2) style(2)
                    base = offset + 8
                    ns_idx    = struct.unpack_from("<i", data, base)[0]
                    name_idx  = struct.unpack_from("<i", data, base + 4)[0]
                    attr_count = struct.unpack_from("<H", data, base + 10)[0]

                    name = strings[name_idx] if 0 <= name_idx < len(strings) else "unknown"
                    stack.append(name)

                    attrs = []
                    attr_base = base + 20
                    for a in range(attr_count):
                        ab = attr_base + a * 20
                        a_ns   = struct.unpack_from("<i", data, ab)[0]
                        a_name = struct.unpack_from("<i", data, ab + 4)[0]
                        a_raw  = struct.unpack_from("<i", data, ab + 8)[0]
                        a_type = struct.unpack_from("<B", data, ab + 15)[0]
                        a_val  = struct.unpack_from("<i", data, ab + 16)[0]

                        aname = strings[a_name] if 0 <= a_name < len(strings) else "attr"
                        if a_ns >= 0 and a_ns < len(strings) and strings[a_ns] == ANDROID_NS:
                            aname = f"android:{aname}"

                        # Décoder la valeur selon le type
                        if a_type == 0x03:  # TYPE_STRING
                            aval = strings[a_raw] if 0 <= a_raw < len(strings) else ""
                        elif a_type == 0x12:  # TYPE_BOOLEAN
                            aval = "true" if a_val else "false"
                        elif a_type == 0x10:  # TYPE_INT_DEC
                            aval = str(a_val)
                        elif a_type == 0x11:  # TYPE_INT_HEX
                            aval = hex(a_val)
                        elif a_type == 0x01:  # TYPE_REFERENCE
                            aval = f"@{hex(a_val)}"
                        else:
                            aval = str(a_val) if a_val else ""

                        attrs.append(f'{aname}="{aval}"')

                    indent = "  " * (len(stack) - 1)
                    attr_str = (" " + " ".join(attrs)) if attrs else ""
                    lines.append(f"{indent}<{name}{attr_str}>")
                except Exception:
                    pass

            elif chunk_type == RES_END:
                try:
                    name_idx = struct.unpack_from("<i", data, offset + 16)[0]
                    name = strings[name_idx] if 0 <= name_idx < len(strings) else (stack[-1] if stack else "unknown")
                    if stack:
                        stack.pop()
                    indent = "  " * len(stack)
                    lines.append(f"{indent}</{name}>")
                except Exception:
                    pass

            offset += max(chunk_size, 8)

        result = "\n".join(lines)
        return result if len(result) > 50 else ""

    def _extract_nsc_via_apktool(apk_content: bytes, decompiler_obj) -> str:
        """
        Fallback : utilise apktool pour décoder le NSC en XML lisible.
        apktool décode automatiquement les AXML en XML texte dans res/xml/.
        """
        if not decompiler_obj.apktool_available:
            return ""
        import tempfile, shutil, subprocess
        temp_dir = tempfile.mkdtemp()
        try:
            apk_path = os.path.join(temp_dir, "app.apk")
            out_dir  = os.path.join(temp_dir, "out")
            with open(apk_path, "wb") as f:
                f.write(apk_content)
            subprocess.run(
                [decompiler_obj._get_cmd("apktool"), "d", apk_path, "-o", out_dir, "-q", "-f"],
                capture_output=True, timeout=60
            )
            # Chercher network_security_config.xml dans res/xml/
            xml_dir = os.path.join(out_dir, "res", "xml")
            if os.path.exists(xml_dir):
                for fname in os.listdir(xml_dir):
                    if "network_security" in fname.lower():
                        fpath = os.path.join(xml_dir, fname)
                        try:
                            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                                return f.read()
                        except Exception:
                            pass
            # Chercher aussi dans res/ directement
            for root, _, files in os.walk(os.path.join(out_dir, "res")):
                for fname in files:
                    if "network_security" in fname.lower() and fname.endswith(".xml"):
                        try:
                            with open(os.path.join(root, fname), "r", encoding="utf-8", errors="replace") as f:
                                return f.read()
                        except Exception:
                            pass
        except Exception:
            pass
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return ""

    # ── Extraction principale ──────────────────────────────────────────────────
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as apk:
            all_names = apk.namelist()

            # Chercher le NSC (binaire AXML dans res/xml/)
            nsc_candidates = [
                n for n in all_names
                if "network_security_config" in n.lower() and n.endswith(".xml")
            ]
            for nsc_name in nsc_candidates:
                try:
                    raw_nsc = apk.read(nsc_name)
                    # Tenter le décodage AXML
                    decoded = decode_axml(raw_nsc)
                    if decoded and "<" in decoded:
                        nsc_xml = decoded
                        break
                    # Si c'est déjà du texte lisible (rare, APK debug)
                    text_try = raw_nsc.decode("utf-8", errors="replace")
                    if "<network-security-config" in text_try or "<base-config" in text_try:
                        nsc_xml = text_try
                        break
                except Exception:
                    pass

            # Extraction des strings brutes (fichiers non-binaires)
            for name in all_names:
                if any(name.endswith(ext) for ext in [".json", ".properties", ".txt", ".js"]):
                    try:
                        raw_parts.append(apk.read(name).decode("utf-8", errors="replace"))
                    except Exception:
                        pass
                # Extraire aussi AndroidManifest.xml (AXML) pour avoir minSdkVersion etc.
                if name == "AndroidManifest.xml":
                    try:
                        manifest_decoded = decode_axml(apk.read(name))
                        if manifest_decoded:
                            raw_parts.append(manifest_decoded)
                    except Exception:
                        pass

    except Exception:
        pass

    # ── Fallback apktool si AXML decoder n'a pas trouvé le NSC ───────────────
    if not nsc_xml:
        nsc_xml = _extract_nsc_via_apktool(content, decompiler)

    results["raw_strings"] = "\n".join(raw_parts)[:50000]
    results["nsc_xml"] = nsc_xml
    
    # 2️⃣ DÉCOMPILATION COMPLÈTE (apktool + jadx)
    results = {
        "endpoints": [],
        "anomalies": [],
        "tls_checks": [],
        "secrets": [],
        "decompilation_status": "pending",
        "nsc_xml": nsc_xml,
        "raw_strings": "",
    }
    
    # Vérifier la disponibilité de jadx
    if not decompiler.jadx_available:
        results["decompilation_status"] = "jadx_not_available"
        results["error"] = "jadx non installé. Toutes les analyses de code doivent être réalisées par JADX. Installez jadx et réessayez."
        return results
    
    # 3️⃣ DÉCOMPILATION avec JADX (code Java source)
    try:
        java_result = decompiler.decompile_java(content)
        
        if java_result.get("error"):
            results["decompilation_status"] = "error"
            results["error"] = java_result["error"]
            return results
        
        results["decompilation_status"] = "success"
        results["java_files_count"] = len(java_result.get("java_files", []))
        
        # 4️⃣ ANALYSE DU CODE JAVA DÉCOMPILÉ
        # Fusionner tout le code Java dans un grand texte
        java_code_full = ""
        for file_info in java_result.get("java_files", []):
            java_code_full += file_info.get("content", "") + "\n"
        
        # 5️⃣ EXTRACTION D'ENDPOINTS depuis le code Java (PLUS PRÉCIS)
        endpoints = extract_endpoints_from_java_code(java_code_full)
        
        # Classification
        for ep in endpoints:
            ep["env"] = classify_environment(ep["value"])
        
        results["endpoints"] = endpoints
        endpoint_tls_analysis = analyze_endpoint_tls_per_endpoint(endpoints, nsc_xml)
        results["endpoint_tls_analysis"] = endpoint_tls_analysis
        results["endpoint_coverage"] = correlate_endpoints_with_nsc(endpoints, nsc_xml) if nsc_xml else []
        tls_map = {item["endpoint"]: item for item in endpoint_tls_analysis}
        for ep in results["endpoints"]:
            if ep["value"] in tls_map:
                ep["tls_info"] = tls_map[ep["value"]]
        
        # 6️⃣ DÉTECTION D'ANOMALIES
        results["anomalies"] = detect_anomalies(endpoints)
        
        # 7️⃣ PARSE NSC
        results["tls_checks"] = parse_nsc_xml(nsc_xml) if nsc_xml else []
        
        # 8️⃣ SECRETS DÉTECTÉS
        results["secrets"] = decompiler.extract_secrets_from_code(java_result.get("java_files", []))
        from analyzer import detect_android_security_patterns
        # Passer la liste des fichiers Java pour permettre la collecte d'évidence précise
        results["java_security_checks"] = detect_android_security_patterns(java_result.get("java_files", []))
        
        # 9️⃣ STATISTIQUES
        results["stats"] = {
            "total": len(endpoints),
            "prod": sum(1 for e in endpoints if e["env"] == "prod"),
            "test": sum(1 for e in endpoints if e["env"] == "test"),
            "cleartext": sum(1 for e in endpoints if e["value"].startswith("http://")),
            "critical": sum(1 for a in results["anomalies"] if a["severity"] == "critical"),
            "high": sum(1 for a in results["anomalies"] if a["severity"] == "high"),
            "secrets_found": len(results["secrets"]),
        }
        
        return results
        
    except KeyboardInterrupt:
        # Gestion des interruptions (rechargement du serveur)
        results["decompilation_status"] = "interrupted"
        results["error"] = "Analyse interrompue (rechargement du serveur)"
        return results
    except Exception as e:
        results["decompilation_status"] = "error"
        results["error"] = f"Erreur inattendue: {str(e)}"
        return results


@app.post("/analyze/folder")
async def analyze_folder(files: List[UploadFile] = File(...)):
    """
    Analyse un dossier entier d'APK en batch.
    Accepte plusieurs fichiers APK et retourne les résultats pour chacun.
    """
    results = {
        "total_files": len(files),
        "analyzed": 0,
        "failed": 0,
        "apk_results": []
    }
    
    for file in files:
        if not file.filename.lower().endswith('.apk'):
            continue
            
        try:
            content = await file.read()
            decompiler = APKDecompiler()
            
            # Extraction NSC
            nsc_xml = ""
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as apk:
                    all_names = apk.namelist()
                    nsc_candidates = [n for n in all_names if "network_security_config" in n.lower()]
                    if nsc_candidates:
                        try:
                            nsc_xml = apk.read(nsc_candidates[0]).decode("utf-8", errors="replace")
                        except Exception:
                            pass
            except:
                pass
            
            # Analyse avec Jadx uniquement ; aucune analyse de code ne doit utiliser zipfile
            apk_result = {
                "filename": file.filename,
                "status": "pending",
                "endpoints": [],
                "anomalies": [],
                "secrets": []
            }
            
            if decompiler.jadx_available:
                try:
                    java_result = decompiler.decompile_java(content)
                    if not java_result.get("error"):
                        java_code_full = ""
                        for file_info in java_result.get("java_files", []):
                            java_code_full += file_info.get("content", "") + "\n"
                        
                        endpoints = extract_endpoints_from_java_code(java_code_full)
                        for ep in endpoints:
                            ep["env"] = classify_environment(ep["value"])
                        
                        endpoint_tls_analysis = analyze_endpoint_tls_per_endpoint(endpoints, nsc_xml)
                        apk_result["endpoint_tls_analysis"] = endpoint_tls_analysis
                        apk_result["endpoint_coverage"] = correlate_endpoints_with_nsc(endpoints, nsc_xml) if nsc_xml else []
                        tls_map = {item["endpoint"]: item for item in endpoint_tls_analysis}
                        for ep in endpoints:
                            if ep["value"] in tls_map:
                                ep["tls_info"] = tls_map[ep["value"]]

                        apk_result["endpoints"] = endpoints
                        apk_result["anomalies"] = detect_anomalies(endpoints)
                        apk_result["secrets"] = decompiler.extract_secrets_from_code(java_result.get("java_files", []))
                        apk_result["status"] = "success"
                    else:
                        apk_result["status"] = "error"
                        apk_result["error"] = java_result["error"]
                except KeyboardInterrupt:
                    apk_result["status"] = "interrupted"
                    apk_result["error"] = "Analyse interrompue (rechargement du serveur)"
                except Exception as e:
                    apk_result["status"] = "error"
                    apk_result["error"] = f"Erreur inattendue: {str(e)}"
            else:
                apk_result["status"] = "error"
                apk_result["error"] = "jadx non disponible. Toutes les analyses de code doivent être réalisées par JADX."
            
            # TLS checks
            apk_result["tls_checks"] = parse_nsc_xml(nsc_xml) if nsc_xml else []
            
            # Stats
            apk_result["stats"] = {
                "endpoints_count": len(apk_result["endpoints"]),
                "prod": sum(1 for e in apk_result["endpoints"] if e["env"] == "prod"),
                "test": sum(1 for e in apk_result["endpoints"] if e["env"] == "test"),
                "cleartext": sum(1 for e in apk_result["endpoints"] if e["value"].startswith("http://")),
                "anomalies_count": len(apk_result["anomalies"]),
                "secrets_found": len(apk_result["secrets"])
            }
            
            results["apk_results"].append(apk_result)
            results["analyzed"] += 1
            
        except Exception as e:
            results["apk_results"].append({
                "filename": file.filename,
                "status": "error",
                "error": str(e)
            })
            results["failed"] += 1
    
    return results


@app.post("/ai/stream")
async def ai_stream(payload: dict):
    if not GROQ_API_KEY:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY non configuree.")

    prompt = payload.get("prompt", "")

    async def event_stream():
        try:
            headers = {
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            }
            body = {
                "model": "llama-3.3-70b-versatile",
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "Tu es un expert en securite mobile Android et en cryptographie reseau. "
                            "Reponds en francais, de facon structuree et concise. "
                            "Utilise des emojis et des listes a puces pour la lisibilite."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": 1500,
                "stream": True,
            }
            async with httpx.AsyncClient(timeout=60) as client:
                async with client.stream("POST", GROQ_URL, json=body, headers=headers) as resp:
                    if resp.status_code != 200:
                        body_err = await resp.aread()
                        yield f"data: {json.dumps({'error': body_err.decode()})}\n\n"
                        return
                    async for line in resp.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        data = line[6:].strip()
                        if not data or data == "[DONE]":
                            continue
                        try:
                            event = json.loads(data)
                            text = event["choices"][0]["delta"].get("content", "")
                            if text:
                                chunk = {"type": "content_block_delta", "delta": {"text": text}}
                                yield f"data: {json.dumps(chunk)}\n\n"
                        except Exception:
                            pass
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/decompile/smali")
async def decompile_smali(file: UploadFile = File(...)):
    """
    Décompile l'APK en Smali (assembleur Android) avec apktool.
    Nécessite: apktool installé sur le système.
    """
    content = await file.read()
    decompiler = APKDecompiler()
    
    if not decompiler.apktool_available:
        raise HTTPException(
            status_code=503,
            detail="apktool non disponible. Installez avec: apt install apktool ou brew install apktool"
        )
    
    result = decompiler.decompile_smali(content)
    return result


@app.post("/decompile/java")
async def decompile_java(file: UploadFile = File(...)):
    """
    Décompile l'APK en code source Java avec jadx.
    Détecte aussi les secrets/endpoints/API keys.
    Nécessite: jadx installé sur le système.
    """
    content = await file.read()
    decompiler = APKDecompiler()
    
    if not decompiler.jadx_available:
        raise HTTPException(
            status_code=503,
            detail="jadx non disponible. Installez avec: apt install jadx ou brew install jadx"
        )
    
    result = decompiler.decompile_java(content)
    
    # Détecter les secrets dans le code Java
    if result["java_files"]:
        result["secrets_detected"] = decompiler.extract_secrets_from_code(result["java_files"])
    
    return result


@app.post("/decompile/full")
async def decompile_full(file: UploadFile = File(...)):
    """
    Décompilation COMPLÈTE de l'APK :
    1. Analyse statique (endpoints, anomalies, TLS checks)
    2. Décompilation Smali (si apktool disponible)
    3. Décompilation Java (si jadx disponible)
    4. Détection de secrets dans le code
    """
    content = await file.read()
    decompiler = APKDecompiler()
    
    # 1️⃣ Analyse statique classique
    results = {"endpoints": [], "nsc_xml": "", "raw_strings": "", "files_found": []}
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as apk:
            all_names = apk.namelist()
            results["files_found"] = [n for n in all_names if any(
                n.endswith(ext) for ext in [".xml", ".json", ".properties", ".smali", ".js"]
            )][:50]
            
            nsc_candidates = [n for n in all_names if "network_security_config" in n.lower()]
            if nsc_candidates:
                try:
                    results["nsc_xml"] = apk.read(nsc_candidates[0]).decode("utf-8", errors="replace")
                except Exception:
                    pass
            
            raw_parts = []
            for name in all_names:
                if any(name.endswith(ext) for ext in [".xml", ".json", ".js", ".properties", ".smali", ".txt"]):
                    try:
                        data = apk.read(name).decode("utf-8", errors="replace")
                        raw_parts.append(data)
                    except Exception:
                        pass
            
            raw_text = "\n".join(raw_parts)
            results["raw_strings"] = raw_text[:50000]
            results["tls_checks"] = parse_nsc_xml(results["nsc_xml"]) if results["nsc_xml"] else []
            
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Fichier APK invalide ou corrompu.")
    
    # 2️⃣ Décompilation Smali
    smali_result = decompiler.decompile_smali(content)
    results["smali"] = smali_result
    
    # 3️⃣ Décompilation Java
    java_result = decompiler.decompile_java(content)
    results["java"] = java_result
    
    # 4️⃣ Analyse du code Java décompilé
    if java_result.get("java_files"):
        java_code_full = "".join([f.get("content", "") + "\n" for f in java_result.get("java_files", [])])
        endpoints = extract_endpoints_from_java_code(java_code_full)
        for ep in endpoints:
            ep["env"] = classify_environment(ep["value"])

        endpoint_tls_analysis = analyze_endpoint_tls_per_endpoint(endpoints, results.get("nsc_xml", ""))
        results["endpoint_tls_analysis"] = endpoint_tls_analysis
        results["endpoint_coverage"] = correlate_endpoints_with_nsc(endpoints, results.get("nsc_xml", ""))
        tls_map = {item["endpoint"]: item for item in endpoint_tls_analysis}
        for ep in endpoints:
            if ep["value"] in tls_map:
                ep["tls_info"] = tls_map[ep["value"]]

        results["endpoints"] = endpoints
        results["anomalies"] = detect_anomalies(endpoints)
        results["secrets"] = decompiler.extract_secrets_from_code(java_result["java_files"])
        from analyzer import detect_android_security_patterns
        # Utiliser la liste des fichiers Java pour des preuves ciblées
        results["java_security_checks"] = detect_android_security_patterns(java_result.get("java_files", []))

    return results


@app.get("/decompile/tools-status")
def decompile_tools_status():
    """
    Vérifie la disponibilité des outils de décompilation sur le système.
    """
    decompiler = APKDecompiler()
    return {
        "apktool": {
            "available": decompiler.apktool_available,
            "cmd_detected": decompiler._get_cmd("apktool") if decompiler.apktool_available else None,
            "status": "✓ Installé" if decompiler.apktool_available else "✗ Non installé",
            "install_cmd": "apt install apktool (Linux) ou brew install apktool (macOS)"
        },
        "jadx": {
            "available": decompiler.jadx_available,
            "cmd_detected": decompiler._get_cmd("jadx") if decompiler.jadx_available else None,
            "status": "✓ Installé" if decompiler.jadx_available else "✗ Non installé",
            "install_cmd": "apt install jadx (Linux) ou brew install jadx (macOS)"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)