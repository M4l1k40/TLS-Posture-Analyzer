import re
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any


# ── Endpoint extraction ────────────────────────────────────────────────────────

URL_RE    = re.compile(r'https?://[^\s"\'<>)\]},]+')
DOMAIN_RE = re.compile(r'(?<![/@\w])([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z]{2,}){1,3})(?![/\w])', re.IGNORECASE)
IP_RE     = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})(?::\d{2,5})?\b')

# ── PATTERNS POUR EXTRAIRE LES ENDPOINTS DU CODE JAVA ──
# Cherche les déclarations de constantes String avec URLs
JAVA_URL_PATTERNS = [
    r'(?:final\s+)?(?:static\s+)?(?:public\s+)?(?:private\s+)?String\s+\w+\s*=\s*["\']([^"\']{10,})["\']',
    r'\.get\(["\']([a-z0-9:/.\-]+)["\']',
    r'\.post\(["\']([a-z0-9:/.\-]+)["\']',
    r'new\s+URL\(["\']([^"\']+)["\']',
    r'new\s+URI\(["\']([^"\']+)["\']',
    r'request\(["\']([a-z0-9:/.\-]+)["\']',
    r'fetch\(["\']([a-z0-9:/.\-]+)["\']',
    r'HttpClient[^;]*["\']([a-z0-9:/.\-]+)["\']',
    r'Retrofit[^;]*["\']([a-z0-9:/.\-]+)["\']',
    r'\.setHeader\(["\']([a-z0-9:/.\-]+)["\']',
]

# Domaines/préfixes à ignorer — namespaces XML, SDK Android, libs internes
NOISE_DOMAINS = {
    "android.com", "google.com", "example.com", "w3.org", "schemas.android.com",
    "xmlns.com", "apache.org", "java.lang", "com.android", "kotlin.io",
    "xmlpull.org", "www.w3.org", "ns.adobe.com", "purl.org",
}

# Préfixes d'URLs à ignorer (namespaces XML, schémas Android, etc.)
NOISE_URL_PREFIXES = (
    "http://schemas.android.com",
    "http://www.w3.org",
    "http://schemas.openxmlformats.org",
    "http://xmlns.jcp.org",
    "http://xmlpull.org",
    "http://ns.adobe.com",
    "http://purl.org",
    "http://java.sun.com",
    "http://www.apache.org",
    "http://maven.apache.org",
)


def extract_endpoints_from_java_code(java_source_code: str) -> List[Dict[str, Any]]:
    """
    Extrait les endpoints depuis le code Java DÉCOMPILÉ.
    Beaucoup plus précis que les regex brutes sur des strings.
    
    Cherche :
    - Déclarations de constantes String avec URLs
    - Appels HTTP (get, post, fetch, etc.)
    - Constructeurs URL/URI
    - Retrofit/HttpClient configurations
    """
    seen = set()
    endpoints = []
    
    # Patterns spécifiques au code Java
    for pattern in JAVA_URL_PATTERNS:
        for m in re.finditer(pattern, java_source_code, re.IGNORECASE):
            try:
                value = m.group(1) if m.lastindex >= 1 else m.group(0)
                
                # Valider que c'est vraiment un endpoint
                if not value or len(value) < 5:
                    continue
                if any(value.startswith(p) for p in NOISE_URL_PREFIXES):
                    continue
                if value in seen:
                    continue
                
                seen.add(value)
                
                # Déterminer le type
                if value.startswith(("http://", "https://")):
                    endpoints.append({"type": "url", "value": value, "source": "java_code"})
                elif re.match(r'^[a-z0-9.-]+\.[a-z]{2,}', value, re.IGNORECASE):
                    endpoints.append({"type": "domain", "value": value, "source": "java_code"})
                elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', value):
                    endpoints.append({"type": "ip", "value": value, "source": "java_code"})
            except:
                pass
    
    # Appliquer aussi les regex standards sur le code Java
    standard_endpoints = extract_endpoints_from_text(java_source_code)
    for ep in standard_endpoints:
        if ep["value"] not in seen:
            seen.add(ep["value"])
            ep["source"] = "java_code"
            endpoints.append(ep)
    
    return endpoints


def extract_endpoints_from_text(text: str) -> List[Dict[str, Any]]:
    seen = set()
    endpoints = []

    # URLs
    for m in URL_RE.finditer(text):
        raw = m.group(0).rstrip(".,;)\"'")
        # Ignorer les namespaces XML et schémas Android
        if any(raw.startswith(prefix) for prefix in NOISE_URL_PREFIXES):
            continue
        if raw not in seen:
            seen.add(raw)
            endpoints.append({"type": "url", "value": raw})

    # Standalone domains
    for m in DOMAIN_RE.finditer(text):
        d = m.group(1).lower()
        if d in seen or d in NOISE_DOMAINS or len(d) < 5:
            continue
        if not re.search(r'\.[a-z]{2,}$', d):
            continue
        seen.add(d)
        endpoints.append({"type": "domain", "value": d})

    # Bare IPs
    for m in IP_RE.finditer(text):
        ip = m.group(0)
        if ip not in seen:
            seen.add(ip)
            endpoints.append({"type": "ip", "value": ip})

    return endpoints


# ── HAR file parser ────────────────────────────────────────────────────────────

def extract_endpoints_from_har(har_text: str) -> List[Dict[str, Any]]:
    """
    Parse un fichier HAR (HTTP Archive) exporté depuis Burp Suite,
    mitmproxy, Chrome DevTools ou Firefox.
    Retourne la liste des endpoints extraits.
    """
    endpoints = []
    seen = set()

    try:
        har = json.loads(har_text)
        entries = har.get("log", {}).get("entries", [])
        for entry in entries:
            url = entry.get("request", {}).get("url", "")
            if url and url not in seen:
                seen.add(url)
                endpoints.append({"type": "url", "value": url, "source": "har"})
    except (json.JSONDecodeError, KeyError, TypeError):
        # Si ce n'est pas du JSON valide, on tente une extraction par regex
        for m in URL_RE.finditer(har_text):
            raw = m.group(0).rstrip(".,;)\"'")
            if raw not in seen:
                seen.add(raw)
                endpoints.append({"type": "url", "value": raw, "source": "har"})

    return endpoints


# ── Environment classification ─────────────────────────────────────────────────

PROD_PATTERNS = re.compile(r'prod|api\.|app\.|www\.|cdn\.|live\.|release', re.IGNORECASE)

# "internal" seul ne suffit pas — doit être accompagné d'un vrai pattern réseau
TEST_PATTERNS = re.compile(r'\b(dev|test|staging|preprod|sandbox|qa|mock|debug|stg|uat)\b', re.IGNORECASE)

# Patterns de noms de classes Java/Android à exclure du classement test/dev
JAVA_CLASS_PATTERN = re.compile(
    r'^(v\d+\.|android\.|androidx\.|com\.|org\.|widget\.|view\.|layout\.|menu\.|fragment\.)',
    re.IGNORECASE
)

# IP émulateur Android standard (pointe vers localhost machine hôte) — pas une anomalie
EMULATOR_IPS = {"10.0.2.2", "10.0.2.15", "10.0.3.2"}


def classify_environment(value: str) -> str:
    # Ne pas classifier les noms de classes Java comme "test"
    if JAVA_CLASS_PATTERN.match(value):
        return "unknown"
    if TEST_PATTERNS.search(value):
        return "test"
    if PROD_PATTERNS.search(value):
        return "prod"
    return "unknown"


# ── Anomaly detection ──────────────────────────────────────────────────────────

SUSPICIOUS_DOMAINS = re.compile(
    r'ngrok|localtunnel|requestbin|webhook\.site|pastebin|pipedream|burpcollaborator|interactsh',
    re.IGNORECASE
)
PRIVATE_IP = re.compile(
    r'^(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+)'
)

# Domaines qui ne sont pas de vraies URLs réseau
NOT_REAL_URL = re.compile(
    r'^(v\d+\.|widget\.|view\.|layout\.|menu\.|fragment\.|android\.|androidx\.)',
    re.IGNORECASE
)


def detect_anomalies(endpoints: List[Dict]) -> List[Dict]:
    anomalies = []
    for ep in endpoints:
        v = ep["value"]
        vl = v.lower()

        # Ignorer les noms de classes Java/Android déguisés en endpoints
        if NOT_REAL_URL.match(v):
            continue

        # Cleartext HTTP — ignorer les namespaces XML et IPs émulateur
        if v.startswith("http://"):
            host = v.replace("http://", "").split("/")[0].split(":")[0]
            if not any(v.startswith(p) for p in NOISE_URL_PREFIXES):
                if host not in EMULATOR_IPS:
                    anomalies.append({"endpoint": v, "issue": "Cleartext HTTP (pas de chiffrement)", "severity": "critical"})

        if SUSPICIOUS_DOMAINS.search(vl):
            anomalies.append({"endpoint": v, "issue": "Domaine de tunneling/debug suspect", "severity": "high"})

        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', v)
        if ip_match:
            ip = ip_match.group(0)
            if ip in EMULATOR_IPS:
                # IP émulateur Android — info seulement, pas une vraie anomalie
                anomalies.append({"endpoint": v, "issue": "IP émulateur Android (10.0.2.2 = localhost hôte) — normal en dev", "severity": "low"})
            elif PRIVATE_IP.match(ip):
                anomalies.append({"endpoint": v, "issue": "IP privée exposée (réseau interne)", "severity": "high"})
            else:
                anomalies.append({"endpoint": v, "issue": "IP publique brute (pas de vérification hostname TLS)", "severity": "medium"})

        # Endpoint test/dev — seulement pour de vraies URLs, pas des noms de classes
        if ep.get("env") == "test" and ep.get("type") == "url":
            anomalies.append({"endpoint": v, "issue": "Endpoint test/dev détecté dans l'APK", "severity": "low"})

    return anomalies


# ── AndroidManifest.xml analyzer ──────────────────────────────────────────────

def parse_manifest(manifest_text: str) -> List[Dict]:
    """
    Analyse AndroidManifest.xml pour les apps sans NSC (avant Android 7).
    Détecte usesCleartextTraffic, debuggable, allowBackup, minSdkVersion.
    """
    checks = []

    cleartext = re.search(r'android:usesCleartextTraffic\s*=\s*["\']?(true)["\']?', manifest_text, re.IGNORECASE)
    checks.append({
        "label": "usesCleartextTraffic (Manifest)",
        "ok": not bool(cleartext),
        "detail": "android:usesCleartextTraffic=true — trafic HTTP non chiffré autorisé !" if cleartext else "Non défini ou false ✓",
        "severity": "critical" if cleartext else "low",
    })

    has_nsc = bool(re.search(r'android:networkSecurityConfig', manifest_text))
    checks.append({
        "label": "Network Security Config déclaré",
        "ok": has_nsc,
        "detail": "NSC référencé dans le Manifest ✓" if has_nsc else "Aucun NSC déclaré — paramètres TLS par défaut de l'OS",
        "severity": "low" if has_nsc else "medium",
    })

    min_sdk = re.search(r'android:minSdkVersion\s*=\s*["\']?(\d+)["\']?', manifest_text)
    if min_sdk:
        sdk = int(min_sdk.group(1))
        ok = sdk >= 24
        checks.append({
            "label": "minSdkVersion / Support NSC",
            "ok": ok,
            "detail": f"minSdkVersion={sdk} → {'NSC supporté (Android 7+) ✓' if ok else '⚠️ Android < 7, NSC non disponible — TLS dépend uniquement de l\'OS'}",
            "severity": "low" if ok else "medium",
        })

    debuggable = re.search(r'android:debuggable\s*=\s*["\']?(true)["\']?', manifest_text, re.IGNORECASE)
    checks.append({
        "label": "Mode debug activé (Manifest)",
        "ok": not bool(debuggable),
        "detail": "android:debuggable=true ⚠️ — à désactiver en production !" if debuggable else "Non debuggable ✓",
        "severity": "high" if debuggable else "low",
    })

    allow_backup = re.search(r'android:allowBackup\s*=\s*["\']?(true)["\']?', manifest_text, re.IGNORECASE)
    checks.append({
        "label": "Backup ADB autorisé (Manifest)",
        "ok": not bool(allow_backup),
        "detail": "android:allowBackup=true — extraction des données via adb backup possible" if allow_backup else "Backup désactivé ✓",
        "severity": "medium" if allow_backup else "low",
    })

    return checks


# ── NSC XML parser ─────────────────────────────────────────────────────────────

def parse_nsc_xml(xml_text: str) -> List[Dict]:
    checks = []

    # ── 1. Cleartext Traffic ──────────────────────────────────────────────────
    cleartext = re.search(r'cleartextTrafficPermitted\s*=\s*["\']?(true)["\']?', xml_text, re.IGNORECASE)
    checks.append({
        "label": "Cleartext Traffic autorisé",
        "ok": not bool(cleartext),
        "detail": "cleartextTrafficPermitted=true trouvé — trafic HTTP non chiffré autorisé !" if cleartext else "Non autorisé ✓",
        "severity": "critical" if cleartext else "low",
    })

    # ── 2. Certificats utilisateur ────────────────────────────────────────────
    user_certs = re.search(r'src\s*=\s*["\']user["\']', xml_text)
    checks.append({
        "label": "Certificats utilisateur approuvés",
        "ok": not bool(user_certs),
        "detail": "Certificats user acceptés — interception MITM triviale" if user_certs else "Seuls les CA système acceptés ✓",
        "severity": "high" if user_certs else "low",
    })

    # ── 3. Version TLS minimale ───────────────────────────────────────────────
    # Cherche tlsVersion (Android 10+) ET minSdkVersion comme fallback
    tls_version = re.search(r'tlsVersion\s*=\s*["\']?(TLSv[\d.]+)["\']?', xml_text, re.IGNORECASE)
    min_sdk = re.search(r'minSdkVersion\s*=\s*["\']?(\d+)["\']?', xml_text)

    if tls_version:
        version_str = tls_version.group(1)
        is_weak = version_str in ("TLSv1.0", "TLSv1.1")
        checks.append({
            "label": "Version TLS minimale déclarée",
            "ok": not is_weak,
            "detail": f"tlsVersion = {version_str} — {'⚠️ version obsolète, utiliser TLSv1.2+' if is_weak else '✓'}",
            "severity": "high" if is_weak else "low",
        })
    elif min_sdk:
        sdk = int(min_sdk.group(1))
        # API 29+ = Android 10 = TLS 1.3 par défaut
        ok = sdk >= 29
        checks.append({
            "label": "Version TLS minimale (via minSdkVersion)",
            "ok": ok,
            "detail": f"minSdkVersion = {sdk} → {'TLS 1.3 par défaut ✓' if sdk >= 29 else 'TLS 1.2 minimum recommandé (API 29+)'}",
            "severity": "low" if ok else "medium",
        })
    else:
        checks.append({
            "label": "Version TLS minimale déclarée",
            "ok": False,
            "detail": "Aucune version TLS ni minSdkVersion spécifiée — dépend de l'OS",
            "severity": "medium",
        })

    # ── 4. Certificate Pinning ────────────────────────────────────────────────
    has_pin_set = bool(re.search(r'<pin-set', xml_text))
    has_pins    = bool(re.search(r'<pin\s', xml_text))

    if has_pin_set and has_pins:
        # Extraire les domaines qui ont des pins
        pinned_domains = re.findall(r'<domain[^>]*>\s*([^<]+)\s*</domain>', xml_text)
        pin_values     = re.findall(r'<pin[^>]*digest=["\']([^"\']+)["\'][^>]*>([^<]+)</pin>', xml_text)
        expiry         = re.search(r'expiration\s*=\s*["\']([^"\']+)["\']', xml_text)

        detail_parts = [f"Pins déclarés pour : {', '.join(pinned_domains) if pinned_domains else 'domaines non parsés'} ✓"]
        detail_parts.append(f"{len(pin_values)} pin(s) SHA-256 configuré(s)")
        if expiry:
            detail_parts.append(f"Expiration : {expiry.group(1)}")
        else:
            detail_parts.append("⚠️ Pas de date d'expiration — risque de blocage permanent si cert change")

        checks.append({
            "label": "Certificate Pinning (NSC)",
            "ok": True,
            "detail": " | ".join(detail_parts),
            "severity": "low",
            "pinned_domains": pinned_domains,
            "pin_count": len(pin_values),
        })
    elif has_pin_set and not has_pins:
        checks.append({
            "label": "Certificate Pinning (NSC)",
            "ok": False,
            "detail": "⚠️ <pin-set> déclaré mais aucun <pin> trouvé — pinning non fonctionnel !",
            "severity": "high",
        })
    else:
        checks.append({
            "label": "Certificate Pinning (NSC)",
            "ok": False,
            "detail": "Aucun pin déclaré — validation CA standard uniquement (MITM possible avec CA compromis)",
            "severity": "high",
        })

    # ── 5. Debug overrides ────────────────────────────────────────────────────
    debug_override = bool(re.search(r'<debug-overrides', xml_text))
    checks.append({
        "label": "Debug overrides présents",
        "ok": not debug_override,
        "detail": "⚠️ <debug-overrides> détecté — certificats user acceptés en debug, à retirer en prod !" if debug_override else "Pas de debug-overrides ✓",
        "severity": "medium" if debug_override else "low",
    })

    # ── 6. HSTS (vérification côté NSC) ──────────────────────────────────────
    # HSTS est côté serveur mais on peut détecter si l'app force HTTPS
    force_https = not bool(cleartext) and bool(re.search(r'<domain-config|<base-config', xml_text))
    checks.append({
        "label": "Trafic HTTPS forcé (base-config)",
        "ok": force_https,
        "detail": "Configuration base-config présente sans cleartext ✓ — vérifier HSTS côté backend (Strict-Transport-Security header)" if force_https else "Aucune base-config HTTPS forcée détectée",
        "severity": "low" if force_https else "medium",
    })

    return checks


# ── Android Security Patterns Detection ───────────────────────────────────────

def detect_android_security_patterns(java_code: str) -> List[Dict]:
    """
    Analyse le code Java décompilé pour détecter les patterns de sécurité Android critiques.
    Vérifications complètes :
    - TrustManager custom (bypass TLS)
    - HostnameVerifier permissif
    - WebView SSL/TLS
    - OkHttp Certificate Pinning
    - Versions TLS et cipher suites
    - HttpUrlConnection configuration
    - SSLContext custom
    - Intercepteurs réseau (credentials)
    - Retrofit configuration
    - Certificats auto-signés
    - WebView mixte content
    - Permissions + Debuggable
    - ProxySelector custom
    - Authenticator custom
    """
    results = []
    
    # ── 1. TrustManager custom ────────────────────────────────────────────────
    has_trustmanager = bool(re.search(r'implements\s+X509TrustManager|extends\s+\w*TrustManager', java_code, re.IGNORECASE))
    
    if has_trustmanager:
        checkserver_empty = bool(re.search(r'checkServerTrusted\s*\([^)]*\)\s*\{[\s\n]*\}', java_code))
        results.append({
            "label": "TrustManager custom",
            "found": True,
            "detail": "checkServerTrusted() vide — TLS bypasse ⚠️ CRITIQUE" if checkserver_empty else "TrustManager custom implémenté",
            "severity": "critical" if checkserver_empty else "high",
            "vulnerable": checkserver_empty,
        })
    else:
        results.append({
            "label": "TrustManager custom",
            "found": False,
            "detail": "Aucun TrustManager custom ✓",
            "severity": "low",
            "vulnerable": False,
        })
    
    # ── 2. HostnameVerifier custom ────────────────────────────────────────────
    has_hostnameverifier = bool(re.search(r'implements\s+HostnameVerifier|AllowAllHostnameVerifier', java_code, re.IGNORECASE))
    
    if has_hostnameverifier:
        verify_true = bool(re.search(r'verify\s*\([^)]*\)\s*\{[^}]*return\s+true[^}]*\}', java_code))
        results.append({
            "label": "HostnameVerifier custom",
            "found": True,
            "detail": "verify() → true — MITM possible ⚠️ CRITIQUE" if verify_true else "HostnameVerifier custom",
            "severity": "critical" if verify_true else "high",
            "vulnerable": verify_true,
        })
    else:
        results.append({
            "label": "HostnameVerifier custom",
            "found": False,
            "detail": "Aucun HostnameVerifier permissif ✓",
            "severity": "low",
            "vulnerable": False,
        })
    
    # ── 3. WebView onReceivedSslError ────────────────────────────────────────
    has_webview_ssl_error = bool(re.search(r'onReceivedSslError\s*\([^)]*\)', java_code, re.IGNORECASE))
    
    if has_webview_ssl_error:
        handler_proceed = bool(re.search(r'handler\.proceed\s*\(\s*\)', java_code))
        results.append({
            "label": "WebView onReceivedSslError",
            "found": True,
            "detail": "handler.proceed() — SSL/TLS errors ignorées ⚠️ CRITIQUE" if handler_proceed else "onReceivedSslError géré",
            "severity": "critical" if handler_proceed else "medium",
            "vulnerable": handler_proceed,
        })
    else:
        results.append({
            "label": "WebView onReceivedSslError",
            "found": False,
            "detail": "Pas de WebView SSL error permissif ✓",
            "severity": "low",
            "vulnerable": False,
        })
    
    # ── 4. OkHttp CertificatePinner ──────────────────────────────────────────
    has_certpinner = bool(re.search(r'CertificatePinner|pin\s*\(["\']', java_code, re.IGNORECASE))
    
    if has_certpinner:
        has_sha256 = bool(re.search(r'sha256/|SHA-256|sha256', java_code, re.IGNORECASE))
        results.append({
            "label": "OkHttp CertificatePinner",
            "found": True,
            "detail": "Certificate Pinning configuré ✓" if has_sha256 else "CertificatePinner détecté",
            "severity": "low" if has_sha256 else "medium",
            "vulnerable": False,
        })
    else:
        results.append({
            "label": "OkHttp CertificatePinner",
            "found": False,
            "detail": "Aucun Certificate Pinning — CA compromise possible",
            "severity": "high",
            "vulnerable": True,
        })
    
    # ── 5. TLS 1.2 minimum ────────────────────────────────────────────────────
    has_tls_config = bool(re.search(r'SSLSocketFactory|setEnabledProtocols|TLSv1\.[23]', java_code, re.IGNORECASE))
    
    if has_tls_config:
        has_weak_tls = bool(re.search(r'SSLv3|TLSv1\.0', java_code))
        results.append({
            "label": "TLS 1.2 minimum",
            "found": True,
            "detail": "TLS faible (SSLv3/1.0) détecté ⚠️" if has_weak_tls else "TLS 1.2+ configuré ✓",
            "severity": "high" if has_weak_tls else "low",
            "vulnerable": has_weak_tls,
        })
    else:
        results.append({
            "label": "TLS 1.2 minimum",
            "found": False,
            "detail": "Config TLS non explicite — dépend de l'OS",
            "severity": "medium",
            "vulnerable": True,
        })
    
    # ── 6. Cipher suites modernes ────────────────────────────────────────────
    has_cipher_spec = bool(re.search(r'ConnectionSpec\.MODERN_TLS|setEnabledCipherSuites', java_code, re.IGNORECASE))
    
    if has_cipher_spec:
        results.append({
            "label": "Cipher suite moderne",
            "found": True,
            "detail": "Cipher suites configurées ✓",
            "severity": "low",
            "vulnerable": False,
        })
    else:
        results.append({
            "label": "Cipher suite moderne",
            "found": False,
            "detail": "Cipher suites non spécifiés — utilise defaults",
            "severity": "medium",
            "vulnerable": True,
        })
    
    # ── 7. HttpURLConnection custom ──────────────────────────────────────────
    has_httpurlconnection = bool(re.search(r'HttpURLConnection|openConnection\s*\(\s*\)', java_code, re.IGNORECASE))
    
    if has_httpurlconnection:
        custom_ssl = bool(re.search(r'setSSLSocketFactory|setDefaultSSLSocketFactory', java_code, re.IGNORECASE))
        results.append({
            "label": "HttpURLConnection custom",
            "found": True,
            "detail": "Config SSL/TLS personnalisée ⚠️" if custom_ssl else "HttpURLConnection utilisé",
            "severity": "high" if custom_ssl else "medium",
            "vulnerable": custom_ssl,
        })
    else:
        results.append({
            "label": "HttpURLConnection custom",
            "found": False,
            "detail": "HttpURLConnection non utilisé ✓",
            "severity": "low",
            "vulnerable": False,
        })
    
    # ── 8. SSLContext personnalisé ───────────────────────────────────────────
    has_sslcontext = bool(re.search(r'SSLContext\.getInstance|\.init\s*\([^)]*TrustManager', java_code, re.IGNORECASE))
    
    if has_sslcontext:
        safe_init = bool(re.search(r'SecureRandom\(\s*\)|getInstance\s*\(\s*["\']TLSv1\.[23]["\']', java_code, re.IGNORECASE))
        results.append({
            "label": "SSLContext custom",
            "found": True,
            "detail": "SSLContext initialisé — vérifier TrustManager ⚠️" if not safe_init else "SSLContext sécurisé",
            "severity": "high" if not safe_init else "low",
            "vulnerable": not safe_init,
        })
    else:
        results.append({
            "label": "SSLContext custom",
            "found": False,
            "detail": "Pas de SSLContext custom ✓",
            "severity": "low",
            "vulnerable": False,
        })
    
    # ── 9. OkHttp Interceptors (credentials exposure) ──────────────────────
    has_interceptor = bool(re.search(r'addInterceptor|NetworkInterceptor', java_code, re.IGNORECASE))
    
    if has_interceptor:
        # Chercher si des credentials/tokens sont passés
        has_tokens = bool(re.search(r'Authorization|Bearer|Token|API[_-]?KEY|Secret|password|credential', java_code, re.IGNORECASE))
        results.append({
            "label": "OkHttp Intercepteurs",
            "found": True,
            "detail": "Credentials/tokens potentiellement exposés ⚠️" if has_tokens else "Intercepteurs configurés",
            "severity": "high" if has_tokens else "medium",
            "vulnerable": has_tokens,
        })
    else:
        results.append({
            "label": "OkHttp Intercepteurs",
            "found": False,
            "detail": "Aucun intercepteur détecté ✓",
            "severity": "low",
            "vulnerable": False,
        })
    
    # ── 10. Retrofit configuration ────────────────────────────────────────────
    has_retrofit = bool(re.search(r'Retrofit\.Builder|\.baseUrl', java_code, re.IGNORECASE))
    
    if has_retrofit:
        insecure_client = bool(re.search(r'newBuilder\s*\(\s*\)|unsafeClient|\.build\s*\(\s*\)', java_code, re.IGNORECASE)) and not has_certpinner
        results.append({
            "label": "Retrofit configuration",
            "found": True,
            "detail": "Retrofit utilisé sans pinning ⚠️" if insecure_client else "Retrofit configuré",
            "severity": "high" if insecure_client else "low",
            "vulnerable": insecure_client,
        })
    else:
        results.append({
            "label": "Retrofit configuration",
            "found": False,
            "detail": "Retrofit non utilisé",
            "severity": "low",
            "vulnerable": False,
        })
    
    # ── 11. Certificats auto-signés acceptés ────────────────────────────────
    accepts_selfsigned = bool(re.search(r'X509Certificate|getAcceptedIssuers\s*\(\s*\)\s*\{[\s\n]*return\s+null|PKIX|getSubjectX500Principal', java_code, re.IGNORECASE))
    
    if accepts_selfsigned:
        results.append({
            "label": "Certificats auto-signés",
            "found": True,
            "detail": "Possibilité d'accepter certificats auto-signés ⚠️",
            "severity": "high",
            "vulnerable": True,
        })
    else:
        results.append({
            "label": "Certificats auto-signés",
            "found": False,
            "detail": "Pas de acceptation auto-signée ✓",
            "severity": "low",
            "vulnerable": False,
        })
    
    # ── 12. WebView mixte content (HTTP + HTTPS) ────────────────────────────
    mixedcontent = bool(re.search(r'setMixedContentMode|MIXED_CONTENT_ALWAYS_ALLOW', java_code, re.IGNORECASE))
    
    if mixedcontent:
        always_allow = bool(re.search(r'MIXED_CONTENT_ALWAYS_ALLOW', java_code))
        results.append({
            "label": "WebView mixte content",
            "found": True,
            "detail": "HTTP + HTTPS autorisé dans WebView ⚠️ CRITIQUE" if always_allow else "Mixte content configuré",
            "severity": "critical" if always_allow else "high",
            "vulnerable": always_allow,
        })
    else:
        results.append({
            "label": "WebView mixte content",
            "found": False,
            "detail": "Pas de mixte content autorisé ✓",
            "severity": "low",
            "vulnerable": False,
        })
    
    # ── 13. Permissions INTERNET + Debuggable ──────────────────────────────
    # Note : Cette info vient du Manifest, pas du code Java, mais on la signale
    results.append({
        "label": "Permissions INTERNET",
        "found": True,  # Presque tous les apps les ont
        "detail": "Vérifier avec Manifest si debuggable=true (risque accru)",
        "severity": "low",
        "vulnerable": False,
    })
    
    # ── 14. ProxySelector custom ─────────────────────────────────────────────
    has_proxyselector = bool(re.search(r'ProxySelector|\.setDefault|getProxyForURL', java_code, re.IGNORECASE))
    
    if has_proxyselector:
        results.append({
            "label": "ProxySelector custom",
            "found": True,
            "detail": "Proxy personnalisé configuré — vérifier sécurité",
            "severity": "high",
            "vulnerable": True,
        })
    else:
        results.append({
            "label": "ProxySelector custom",
            "found": False,
            "detail": "Pas de ProxySelector custom ✓",
            "severity": "low",
            "vulnerable": False,
        })
    
    # ── 15. Authenticator custom ─────────────────────────────────────────────
    has_authenticator = bool(re.search(r'Authenticator|getPasswordAuthentication|setDefault', java_code, re.IGNORECASE))
    
    if has_authenticator:
        results.append({
            "label": "Authenticator custom",
            "found": True,
            "detail": "Authentification personnalisée — vérifier credentials handling ⚠️",
            "severity": "high",
            "vulnerable": True,
        })
    else:
        results.append({
            "label": "Authenticator custom",
            "found": False,
            "detail": "Pas d'Authenticator custom ✓",
            "severity": "low",
            "vulnerable": False,
        })
    
    # ── 16. OkHttp Endpoint verification disabled ───────────────────────────
    endpoint_disabled = bool(re.search(r'endpointVerification\s*=\s*false|ENDPOINT_VERIFICATION_DISABLED', java_code, re.IGNORECASE))
    
    if endpoint_disabled:
        results.append({
            "label": "OkHttp Endpoint verification",
            "found": True,
            "detail": "Endpoint verification désactivée ⚠️ CRITIQUE",
            "severity": "critical",
            "vulnerable": True,
        })
    else:
        results.append({
            "label": "OkHttp Endpoint verification",
            "found": False,
            "detail": "Endpoint verification activée ✓",
            "severity": "low",
            "vulnerable": False,
        })
    
    # ── 17. Cleartext traffic permitted ──────────────────────────────────────
    cleartext_explicit = bool(re.search(r'usesCleartextTraffic\s*=\s*true|cleartextTrafficPermitted\s*=\s*true', java_code, re.IGNORECASE))
    
    if cleartext_explicit:
        results.append({
            "label": "Cleartext traffic autorisé",
            "found": True,
            "detail": "Trafic HTTP non chiffré autorisé ⚠️ CRITIQUE",
            "severity": "critical",
            "vulnerable": True,
        })
    else:
        results.append({
            "label": "Cleartext traffic autorisé",
            "found": False,
            "detail": "HTTPS requis ✓",
            "severity": "low",
            "vulnerable": False,
        })
    
    return results


# ── ADVANCED FEATURES ── Clustering, TLS Analysis, Certificate Validation ──────────

def cluster_endpoints_by_domain(endpoints: List[Dict]) -> Dict[str, Any]:
    """
    Groupe les endpoints par domaine/service pour détection anomalies avancée.
    Retourne:
    - Clusters par domaine
    - Récapitulatif par cluster (env, cleartext, count)
    - Anomalies inter-clusters
    """
    clusters = {}
    
    for ep in endpoints:
        # Extraire le domaine principal
        value = ep.get("value", "")
        domain = None
        
        if ep.get("type") == "url":
            # https://api.prod.example.com/path → api.prod.example.com
            domain = value.split("://")[-1].split("/")[0].split(":")[0]
        elif ep.get("type") == "domain":
            domain = value.split("/")[0]
        elif ep.get("type") == "ip":
            # Group IPs by subnet
            domain = ".".join(value.split(".")[:3]) + ".0/24"
        
        if not domain:
            continue
        
        if domain not in clusters:
            clusters[domain] = {
                "domain": domain,
                "endpoints": [],
                "environments": set(),
                "cleartext": 0,
                "https": 0,
                "severity_max": "low",
            }
        
        clusters[domain]["endpoints"].append(ep)
        clusters[domain]["environments"].add(ep.get("env", "unknown"))
        
        if ep.get("value", "").startswith("http://"):
            clusters[domain]["cleartext"] += 1
        else:
            clusters[domain]["https"] += 1
        
        # Track max severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        ep_severity = ep.get("severity", "low")
        cluster_severity = severity_order.get(clusters[domain]["severity_max"], 0)
        if severity_order.get(ep_severity, 0) > cluster_severity:
            clusters[domain]["severity_max"] = ep_severity
    
    # Détecter anomalies inter-clusters
    anomalies_cluster = []
    for domain, data in clusters.items():
        # Anomalie 1 : Cleartext + HTTPS sur même domaine
        if data["cleartext"] > 0 and data["https"] > 0:
            anomalies_cluster.append({
                "domain": domain,
                "type": "mixed_protocol",
                "detail": f"⚠️ Domaine mélangé: {data['cleartext']}x HTTP + {data['https']}x HTTPS",
                "severity": "high",
            })
        
        # Anomalie 2 : Prod + Test sur même domaine
        if len(data["environments"]) > 1 and "prod" in data["environments"] and "test" in data["environments"]:
            anomalies_cluster.append({
                "domain": domain,
                "type": "mixed_environment",
                "detail": f"⚠️ Domaine mixte: prod + test ({data['environments']})",
                "severity": "high",
            })
        
        # Anomalie 3 : Tous cleartext pour un domaine
        if data["cleartext"] > 0 and data["https"] == 0:
            anomalies_cluster.append({
                "domain": domain,
                "type": "all_cleartext",
                "detail": f"⚠️ Domaine 100% cleartext ({data['cleartext']} endpoints)",
                "severity": "critical" if "prod" in data["environments"] else "high",
            })
        
        # Anomalie 4 : Prod cleartext
        if data["cleartext"] > 0 and "prod" in data["environments"]:
            anomalies_cluster.append({
                "domain": domain,
                "type": "prod_cleartext",
                "detail": f"⚠️ Production avec HTTP: {data['cleartext']} endpoints",
                "severity": "critical",
            })
    
    return {
        "clusters": {k: {**v, "environments": list(v["environments"])} for k, v in clusters.items()},
        "anomalies": anomalies_cluster,
        "total_clusters": len(clusters),
        "total_endpoints_clustered": sum(len(c["endpoints"]) for c in clusters.values()),
    }


def analyze_endpoint_tls_per_endpoint(endpoints: List[Dict], nsc_xml: str = "") -> List[Dict]:
    """
    Analyse TLS par endpoint (simulation basée sur patterns + NSC).
    Retourne pour chaque endpoint:
    - TLS version probable
    - Cipher suites
    - Certificat chain validité
    - Risk level
    """
    endpoint_tls_analysis = []
    
    # Parse NSC pour extraire TLS min global
    nsc_tls_min = "TLSv1.2"  # Default
    nsc_tls_match = re.search(r'tlsVersion\s*=\s*["\']?(TLSv[\d.]+)', nsc_xml, re.IGNORECASE)
    if nsc_tls_match:
        nsc_tls_min = nsc_tls_match.group(1)
    
    for ep in endpoints:
        value = ep.get("value", "")
        ep_type = ep.get("type", "")
        
        # Déterminer TLS version probable
        tls_version = nsc_tls_min
        if value.startswith("http://"):
            tls_version = "None (HTTP cleartext)"
            cipher_suites = "N/A"
            cert_valid = False
        else:
            # Heuristique : vérifier patterns de TLS
            if "legacy" in value.lower() or "old" in value.lower():
                tls_version = "TLSv1.2 (legacy)"
            elif "api" in value.lower() and "modern" in value.lower():
                tls_version = "TLSv1.3"
            
            # Default cipher suites estimation
            if tls_version == "TLSv1.3":
                cipher_suites = "AES-GCM, ChaCha20-Poly1305"
            else:
                cipher_suites = "ECDHE-RSA-AES256-GCM-SHA384, TLS_AES_256_GCM_SHA384"
            
            cert_valid = True
        
        risk_level = "low"
        if value.startswith("http://"):
            risk_level = "critical"
        elif tls_version.startswith("TLSv1.0") or tls_version.startswith("SSLv"):
            risk_level = "critical"
        elif tls_version == "TLSv1.1":
            risk_level = "high"
        elif tls_version == "TLSv1.2":
            risk_level = "low"
        elif tls_version == "TLSv1.3":
            risk_level = "low"
        
        endpoint_tls_analysis.append({
            "endpoint": value,
            "type": ep_type,
            "tls_version": tls_version,
            "cipher_suites": cipher_suites,
            "certificate_valid": cert_valid,
            "risk": risk_level,
            "recommendation": "Upgrade to TLS 1.3" if tls_version != "TLSv1.3" else "✓ TLS 1.3",
        })
    
    return endpoint_tls_analysis


def validate_certificate_pins(nsc_xml: str, endpoints: List[Dict]) -> List[Dict]:
    """
    Valide les pins déclarés dans NSC.
    Simulation: parse pins et recommande validations.
    Retourne:
    - Domaines avec pins
    - Détails des pins
    - Recommandations de lifecycle
    """
    pin_validation = []
    
    # Extraire pin-set
    pin_sets = re.findall(r'<pin-set[^>]*>(.*?)</pin-set>', nsc_xml, re.DOTALL)
    
    if not pin_sets:
        return [{
            "status": "no_pins",
            "detail": "Aucun Certificate Pinning déclaré",
            "recommendation": "Implémenter NSC pinning pour les domaines critiques",
            "severity": "high",
        }]
    
    for pin_set in pin_sets:
        # Extraire domaines
        domains = re.findall(r'<domain[^>]*>\s*([^<]+)\s*</domain>', pin_set)
        
        # Extraire pins
        pins = re.findall(r'<pin\s+digest=["\']([^"\']+)["\'][^>]*>\s*([^<]+)\s*</pin>', pin_set)
        
        # Extraire expiration
        expiration = re.search(r'expiration\s*=\s*["\']([^"\']+)["\']', pin_set)
        
        # Extraire backup pins recommendation
        pin_count = len(pins)
        has_backup = pin_count >= 2
        
        pin_validation.append({
            "status": "pins_found",
            "domains": domains,
            "pin_count": pin_count,
            "digest_types": ["SHA-256" if "sha256" in p[0].lower() else p[0] for p in pins],
            "expiration": expiration.group(1) if expiration else "No expiration set",
            "has_backup_pins": has_backup,
            "severity": "low" if has_backup else "medium",
            "recommendation": "✓ Multiple pins configured (backup pins present)" if has_backup else "⚠️ Add backup pins (min 2 pins recommended)",
        })
    
    return pin_validation


def parse_proxy_log_advanced(log_text: str) -> Dict[str, Any]:
    """
    Parse des logs proxy avancés (CONNECT/GET headers, credentials, patterns).
    Accepte formats: texte brut HTTP requests, Burp logs, mitmproxy, etc.
    """
    parsed = {
        "requests": [],
        "credentials_found": [],
        "suspicious_patterns": [],
        "domains": set(),
        "ports": set(),
    }
    
    # Pattern CONNECT requests (proxy tunneling)
    connect_pattern = r'CONNECT\s+([\w\.-]+):(\d+)\s+HTTP'
    for match in re.finditer(connect_pattern, log_text, re.IGNORECASE):
        domain, port = match.groups()
        parsed["domains"].add(domain)
        parsed["ports"].add(int(port))
        parsed["requests"].append({
            "method": "CONNECT",
            "domain": domain,
            "port": int(port),
            "type": "tunneling",
        })
    
    # Pattern GET/POST requests
    http_pattern = r'(GET|POST|PUT|DELETE)\s+(https?://[^\s]+)\s+HTTP'
    for match in re.finditer(http_pattern, log_text, re.IGNORECASE):
        method, url = match.groups()
        parsed["requests"].append({
            "method": method,
            "url": url,
            "type": "http_request",
        })
    
    # Detect credentials in headers
    credential_patterns = [
        (r'Authorization:\s*Bearer\s+(\S+)', "Bearer token"),
        (r'Authorization:\s*Basic\s+(\S+)', "Basic auth"),
        (r'X-API-Key:\s*(\S+)', "API key"),
        (r'Cookie:\s*([^;]+)', "Session cookie"),
    ]
    
    for pattern, cred_type in credential_patterns:
        for match in re.finditer(pattern, log_text, re.IGNORECASE):
            parsed["credentials_found"].append({
                "type": cred_type,
                "value_sample": match.group(1)[:20] + "...",
                "severity": "high",
            })
    
    # Detect suspicious patterns
    suspicious = [
        (r'curl\s+-k|--insecure', "Curl with -k (SSL verify disabled)"),
        (r'Proxy-Authorization', "Proxy authentication used"),
        (r'X-Forwarded-For.*(?:10\.|192\.168|172\.)', "Private IP in X-Forwarded-For"),
    ]
    
    for pattern, description in suspicious:
        if re.search(pattern, log_text, re.IGNORECASE):
            parsed["suspicious_patterns"].append({
                "pattern": description,
                "severity": "medium",
            })
    
    return {
        **parsed,
        "domains": list(parsed["domains"]),
        "ports": list(parsed["ports"]),
    }


def detect_anomaly_baseline(endpoints: List[Dict], anomalies: List[Dict]) -> Dict[str, Any]:
    """
    ML-basé baseline pour détection anomalies avancées.
    Utilise simple heuristics pour:
    - Domaines anormaux (TLD rare, longueur anormale)
    - IPs privées exposées
    - Patterns de trafic anormaux
    """
    baseline = {
        "normal_endpoints": [],
        "anomalous_endpoints": [],
        "baseline_score": 100,
        "risk_indicators": [],
    }
    
    for ep in endpoints:
        value = ep.get("value", "")
        anomaly_score = 0
        anomaly_reasons = []
        
        # Heuristique 1: Domain length
        if ep.get("type") == "domain" or ep.get("type") == "url":
            domain = value.split("://")[-1].split("/")[0] if "://" in value else value.split("/")[0]
            if len(domain) > 50:
                anomaly_score += 10
                anomaly_reasons.append("Domain name unusually long")
            elif len(domain) < 5:
                anomaly_score += 5
                anomaly_reasons.append("Domain name too short")
        
        # Heuristique 2: Rare TLD
        if re.search(r'\.(tk|ml|ga|cf|xyz|top|loan|download)$', value, re.IGNORECASE):
            anomaly_score += 20
            anomaly_reasons.append("Rare/suspicious TLD detected")
        
        # Heuristique 3: Private IP exposition
        if re.search(r'192\.168|10\.\d|172\.(1[6-9]|2\d|3[01])', value):
            anomaly_score += 30
            anomaly_reasons.append("Private IP exposed in APK")
        
        # Heuristique 4: Cleartext
        if value.startswith("http://"):
            anomaly_score += 25
            anomaly_reasons.append("Cleartext HTTP protocol")
        
        # Heuristique 5: Test environment in prod
        if ep.get("env") == "test":
            anomaly_score += 15
            anomaly_reasons.append("Test environment endpoint")
        
        if anomaly_score > 20:
            baseline["anomalous_endpoints"].append({
                "endpoint": value,
                "anomaly_score": anomaly_score,
                "reasons": anomaly_reasons,
                "severity": "critical" if anomaly_score > 50 else "high" if anomaly_score > 30 else "medium",
            })
            baseline["baseline_score"] -= (anomaly_score / 10)
        else:
            baseline["normal_endpoints"].append(value)
    
    # Risk indicators
    baseline["risk_indicators"] = [
        {"indicator": "Anomalous endpoints count", "value": len(baseline["anomalous_endpoints"])},
        {"indicator": "Normal endpoints count", "value": len(baseline["normal_endpoints"])},
        {"indicator": "Overall baseline score", "value": max(0, baseline["baseline_score"])},
    ]
    
    return baseline


def query_ct_logs(domain: str) -> Dict[str, Any]:
    """
    Simule une query aux Certificate Transparency logs.
    Note: implémentation real nécessiterait requête API externe.
    """
    # Simulation de résultats CT logs
    return {
        "domain": domain,
        "status": "simulated",
        "warning": "Vérification CT logs requiert API externe (Google CT API)",
        "recommendation": "Intégrer google.com/log/ct requête pour production",
        "certificates": [
            {"issuer": "Let's Encrypt", "not_before": "2024-01-01", "not_after": "2025-01-01"},
        ],
    }


def calculate_owasp_cwe_score(endpoints: List[Dict], nsc_checks: List[Dict], anomalies: List[Dict]) -> Dict[str, Any]:
    """
    Calcule un score de sécurité basé sur OWASP Mobile Top 10 + CWE.
    Retourne score /100 avec breakdown par catégorie.
    """
    score = 100
    findings = []
    
    # CWE-295: Improper Certificate Validation
    cleartext_count = sum(1 for ep in endpoints if ep.get("value", "").startswith("http://"))
    if cleartext_count > 0:
        penalty = min(20, cleartext_count * 5)
        score -= penalty
        findings.append({
            "cwe": "CWE-295",
            "title": "Improper Certificate Validation",
            "severity": "CRITICAL" if cleartext_count > 3 else "HIGH",
            "penalty": penalty,
        })
    
    # CWE-327: Use of Weak Cryptography
    weak_tls = any("SSLv3" in str(c) or "TLSv1.0" in str(c) for c in nsc_checks)
    if weak_tls:
        score -= 15
        findings.append({
            "cwe": "CWE-327",
            "title": "Use of Weak Cryptography",
            "severity": "HIGH",
            "penalty": 15,
        })
    
    # OWASP M2: Insecure Data Storage/Transport
    private_ips = sum(1 for ep in endpoints if re.search(r'192\.168|10\.|172\.(1[6-9]|2\d|3[01])', ep.get("value", "")))
    if private_ips > 0:
        score -= min(10, private_ips * 3)
        findings.append({
            "owasp": "M2",
            "title": "Insecure Data Transport",
            "severity": "MEDIUM",
            "penalty": min(10, private_ips * 3),
        })
    
    # Certificate Pinning missing
    has_pinning = any("pin" in str(c).lower() for c in nsc_checks)
    if not has_pinning and len(endpoints) > 5:
        score -= 10
        findings.append({
            "owasp": "M2",
            "title": "Missing Certificate Pinning",
            "severity": "MEDIUM",
            "penalty": 10,
        })
    
    return {
        "final_score": max(0, score),
        "max_score": 100,
        "percentage": f"{max(0, score)}%",
        "rating": "Excellent" if score >= 80 else "Good" if score >= 60 else "Fair" if score >= 40 else "Poor",
        "findings": findings,
        "recommendations": [
            "Upgrade to TLS 1.3 for all endpoints" if weak_tls else None,
            "Remove cleartext HTTP endpoints" if cleartext_count > 0 else None,
            "Implement Certificate Pinning for critical domains" if not has_pinning else None,
        ],
    }