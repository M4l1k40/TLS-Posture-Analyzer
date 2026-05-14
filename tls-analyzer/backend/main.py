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
    return {
        "endpoints": endpoints,
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
    
    # 1️⃣ EXTRACTION RAPIDE du NSC (zipfile)
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
    
    # 2️⃣ DÉCOMPILATION COMPLÈTE (apktool + jadx)
    results = {
        "endpoints": [],
        "anomalies": [],
        "tls_checks": [],
        "secrets": [],
        "decompilation_status": "pending",
        "nsc_xml": nsc_xml,
    }
    
    # Vérifier la disponibilité de jadx
    if not decompiler.jadx_available:
        results["decompilation_status"] = "jadx_not_available"
        results["error"] = "jadx non installé. Installez avec: apt install jadx"
        
        # Fallback : utiliser l'ancienne méthode (zipfile)
        try:
            from analyzer import detect_android_security_patterns
            with zipfile.ZipFile(io.BytesIO(content)) as apk:
                all_names = apk.namelist()
                raw_parts = []
                smali_parts = []
                for name in all_names:
                    if any(name.endswith(ext) for ext in [".xml", ".json", ".js", ".properties", ".smali", ".txt"]):
                        try:
                            data = apk.read(name).decode("utf-8", errors="replace")
                            raw_parts.append(data)
                            if name.endswith(".smali"):
                                smali_parts.append(data)
                        except:
                            pass
                raw_text = "\n".join(raw_parts)
                endpoints = extract_endpoints_from_text(raw_text)
                for ep in endpoints:
                    ep["env"] = classify_environment(ep["value"])
                    ep["source"] = "zipfile_fallback"
                results["endpoints"] = endpoints
                results["anomalies"] = detect_anomalies(endpoints)
                results["tls_checks"] = parse_nsc_xml(nsc_xml) if nsc_xml else []
                # Analyse TLS statique sur le Smali ou raw (fallback jadx)
                from analyzer import detect_android_security_patterns
                analysis_code = "\n".join(smali_parts) if smali_parts else raw_text
                results["java_security_checks"] = detect_android_security_patterns(analysis_code)
                results["java_security_checks_source"] = "smali_fallback" if smali_parts else "raw_fallback"
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    # 3️⃣ DÉCOMPILATION avec JADX (code Java source)
    try:
        java_result = decompiler.decompile_java(content)
        
        if java_result.get("error"):
            results["decompilation_status"] = "error"
            results["error"] = java_result["error"]
            # Fallback to zipfile method if decompilation fails
            try:
                from analyzer import detect_android_security_patterns
                with zipfile.ZipFile(io.BytesIO(content)) as apk:
                    all_names = apk.namelist()
                    raw_parts = []
                    smali_parts = []
                    for name in all_names:
                        if any(name.endswith(ext) for ext in [".xml", ".json", ".js", ".properties", ".smali", ".txt"]):
                            try:
                                data = apk.read(name).decode("utf-8", errors="replace")
                                raw_parts.append(data)
                                if name.endswith(".smali"):
                                    smali_parts.append(data)
                            except:
                                pass
                    raw_text = "\n".join(raw_parts)
                    endpoints = extract_endpoints_from_text(raw_text)
                    for ep in endpoints:
                        ep["env"] = classify_environment(ep["value"])
                        ep["source"] = "zipfile_fallback_after_jadx_error"
                    results["endpoints"] = endpoints
                    results["anomalies"] = detect_anomalies(endpoints)
                    results["tls_checks"] = parse_nsc_xml(nsc_xml) if nsc_xml else []
                    # Analyse TLS statique sur le Smali (fallback jadx)
                    if smali_parts:
                        smali_code = "\n".join(smali_parts)
                        results["java_security_checks"] = detect_android_security_patterns(smali_code)
                        results["java_security_checks_source"] = "smali_fallback"
            except Exception as fallback_e:
                results["error"] += f" | Fallback aussi échoué: {str(fallback_e)}"
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
        
        # 6️⃣ DÉTECTION D'ANOMALIES
        results["anomalies"] = detect_anomalies(endpoints)
        
        # 7️⃣ PARSE NSC
        results["tls_checks"] = parse_nsc_xml(nsc_xml) if nsc_xml else []
        
        # 8️⃣ SECRETS DÉTECTÉS
        results["secrets"] = decompiler.extract_secrets_from_code(java_result.get("java_files", []))
        from analyzer import detect_android_security_patterns
        results["java_security_checks"] = detect_android_security_patterns(java_code_full)
        
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
            
            # Analyse avec Jadx si disponible, sinon fallback zipfile
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
                # Fallback: zipfile
                try:
                    with zipfile.ZipFile(io.BytesIO(content)) as apk:
                        all_names = apk.namelist()
                        raw_parts = []
                        for name in all_names:
                            if any(name.endswith(ext) for ext in [".xml", ".json", ".js", ".properties"]):
                                try:
                                    data = apk.read(name).decode("utf-8", errors="replace")
                                    raw_parts.append(data)
                                except:
                                    pass
                        
                        from analyzer import extract_endpoints_from_text
                        raw_text = "\n".join(raw_parts)
                        endpoints = extract_endpoints_from_text(raw_text)
                        for ep in endpoints:
                            ep["env"] = classify_environment(ep["value"])
                        
                        apk_result["endpoints"] = endpoints
                        apk_result["anomalies"] = detect_anomalies(endpoints)
                        apk_result["status"] = "success_fallback"
                except Exception as e:
                    apk_result["status"] = "error"
                    apk_result["error"] = str(e)
            
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
            endpoints = extract_endpoints_from_text(raw_text)
            for ep in endpoints:
                ep["env"] = classify_environment(ep["value"])
            results["endpoints"] = endpoints
            results["anomalies"] = detect_anomalies(endpoints)
            results["tls_checks"] = parse_nsc_xml(results["nsc_xml"]) if results["nsc_xml"] else []
            
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Fichier APK invalide ou corrompu.")
    
    # 2️⃣ Décompilation Smali
    smali_result = decompiler.decompile_smali(content)
    results["smali"] = smali_result
    
    # 3️⃣ Décompilation Java
    java_result = decompiler.decompile_java(content)
    results["java"] = java_result
    
    # 4️⃣ Secrets détectés + analyse sécurité TLS sur le code Java
    if java_result.get("java_files"):
        results["secrets"] = decompiler.extract_secrets_from_code(java_result["java_files"])
        from analyzer import detect_android_security_patterns
        java_code_full = "\n".join(f.get("content", "") for f in java_result["java_files"])
        results["java_security_checks"] = detect_android_security_patterns(java_code_full)
    
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