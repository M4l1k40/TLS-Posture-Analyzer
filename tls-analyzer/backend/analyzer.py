import re
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any


# ── Endpoint extraction ────────────────────────────────────────────────────────

URL_RE    = re.compile(r'https?://[^\s"\'<>)\]},]+')
DOMAIN_RE = re.compile(r'(?<![/@\w])([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z]{2,}){1,3})(?![/\w])', re.IGNORECASE)
IP_RE     = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})(?::\d{2,5})?\b')

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