from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import uvicorn
import json
import zipfile
import io
import os
import httpx
import traceback

from analyzer import (
    extract_endpoints_from_text,
    extract_endpoints_from_har,
    parse_nsc_xml,
    parse_manifest,
    detect_anomalies,
    classify_environment,
)

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


@app.post("/analyze/text")
async def analyze_text(
    apk_text:   str = Form(default=""),
    proxy_text: str = Form(default=""),
    nsc_xml:    str = Form(default=""),
):
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
    content = await file.read()
    results = {"endpoints": [], "nsc_xml": "", "raw_strings": "", "files_found": []}
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as apk:
            all_names = apk.namelist()
            results["files_found"] = [n for n in all_names if any(
                n.endswith(ext) for ext in [".xml", ".json", ".properties", ".smali", ".js"]
            )][:50]

            # Extraction automatique du NSC depuis l'APK
            nsc_candidates = [n for n in all_names if "network_security_config" in n.lower()]
            if nsc_candidates:
                try:
                    results["nsc_xml"] = apk.read(nsc_candidates[0]).decode("utf-8", errors="replace")
                except Exception:
                    pass

            # Extraction et analyse du AndroidManifest.xml
            manifest_text = ""
            if "AndroidManifest.xml" in all_names:
                try:
                    manifest_text = apk.read("AndroidManifest.xml").decode("utf-8", errors="replace")
                except Exception:
                    pass
            results["manifest_checks"] = parse_manifest(manifest_text) if manifest_text else []

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
            # Fusionner NSC checks + Manifest checks dans tls_checks
            nsc_checks      = parse_nsc_xml(results["nsc_xml"]) if results["nsc_xml"] else []
            manifest_checks = results.get("manifest_checks", [])
            results["tls_checks"] = nsc_checks + manifest_checks
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Fichier APK invalide ou corrompu.")
    return results


@app.post("/analyze/har")
async def analyze_har(file: UploadFile = File(...)):
    """
    Import automatique d'un fichier HAR (Burp Suite, mitmproxy, Chrome DevTools).
    Extrait tous les endpoints contactés par l'application sans copier-coller manuel.
    """
    content = await file.read()
    try:
        har_text = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Impossible de lire le fichier HAR.")

    endpoints = extract_endpoints_from_har(har_text)
    for ep in endpoints:
        ep["env"] = classify_environment(ep["value"])

    anomalies = detect_anomalies(endpoints)

    return {
        "endpoints": endpoints,
        "anomalies": anomalies,
        "tls_checks": [],
        "source": "har",
        "stats": {
            "total":     len(endpoints),
            "prod":      sum(1 for e in endpoints if e["env"] == "prod"),
            "test":      sum(1 for e in endpoints if e["env"] == "test"),
            "cleartext": sum(1 for e in endpoints if e["value"].startswith("http://")),
            "critical":  sum(1 for a in anomalies if a["severity"] == "critical"),
            "high":      sum(1 for a in anomalies if a["severity"] == "high"),
        }
    }


@app.post("/ai/stream")
async def ai_stream(payload: dict):
    if not GROQ_API_KEY:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY non configuree.")

    prompt = payload.get("prompt", "")
    print(f"[AI] Prompt length: {len(prompt)} chars")
    print(f"[AI] Groq Key prefix: {GROQ_API_KEY[:15]}...")

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
                    print(f"[AI] Groq response status: {resp.status_code}")
                    if resp.status_code != 200:
                        body_err = await resp.aread()
                        print(f"[AI] Error: {body_err}")
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
                        except Exception as e:
                            print(f"[AI] Parse error: {e}")
        except Exception as e:
            print(f"[AI] Exception: {traceback.format_exc()}")
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)