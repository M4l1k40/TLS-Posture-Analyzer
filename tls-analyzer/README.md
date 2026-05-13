# 🔐 TLS Posture Analyzer

**Outil d'audit défensif du transport réseau Android**  
Analyse la configuration TLS/réseau d'une application Android : endpoints, Network Security Config, anomalies, et recommandations IA.

---

## 📋 Prérequis

| Outil | Version min | Vérification |
|-------|-------------|--------------|
| Python | 3.9+ | `python3 --version` |
| Node.js | 18+ | `node --version` |
| npm | 9+ | `npm --version` |
| Clé API Anthropic | — | https://console.anthropic.com |

---

## 🚀 Installation & Lancement

### Option 1 — Script automatique (recommandé)

**Linux / macOS :**
```bash
chmod +x start.sh
./start.sh
```

**Windows :**
```
Double-clic sur start.bat
```

### Option 2 — Manuel

**1. Configurer la clé API :**
```bash
cp backend/.env.example backend/.env
# Éditez backend/.env et renseignez votre clé :
# ANTHROPIC_API_KEY=sk-ant-VOTRE_CLE
```

**2. Backend :**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**3. Frontend (autre terminal) :**
```bash
cd frontend
npm install
npm run dev
```

**4. Ouvrir :** http://localhost:5173

---

## 📁 Structure du projet

```
tls-analyzer/
├── backend/
│   ├── main.py           # API FastAPI — routes, proxy IA
│   ├── analyzer.py       # Moteur d'analyse : parsing, anomalies, NSC
│   ├── requirements.txt  # Dépendances Python
│   └── .env.example      # Template clé API
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx       # Interface principale (5 onglets)
│   │   ├── api.js        # Client HTTP vers le backend
│   │   ├── main.jsx      # Point d'entrée React
│   │   └── index.css     # Styles globaux (dark theme)
│   ├── index.html
│   ├── package.json
│   └── vite.config.js    # Proxy /api → backend:8000
│
├── start.sh              # Lanceur Linux/macOS
├── start.bat             # Lanceur Windows
└── README.md
```

---

## 🔍 Fonctionnalités

### Onglet 1 — Entrées
- **Upload APK réel** : extraction automatique des strings, du NSC, des endpoints (zipfile Python)
- **Texte APK** : coller l'output de `strings classes.dex`, smali, ressources
- **Logs proxy** : Burp Suite, mitmproxy, Charles Proxy
- **NSC XML** : `res/xml/network_security_config.xml`
- Bouton **Démo** pour tester sans APK

### Onglet 2 — Endpoints
- Inventaire complet : URLs, domaines, IPs brutes
- Classification automatique **prod / test / unknown**
- Filtre par environnement + recherche textuelle
- Highlight rouge des URLs en **HTTP clair**
- Métriques : total, prod, test, cleartext

### Onglet 3 — Checks TLS
- **Analyse statique NSC** :
  - `cleartextTrafficPermitted` → critique si true
  - Certificats utilisateur approuvés → MITM trivial
  - `<pin-set>` présent ou absent
  - `<debug-overrides>` en production
  - Version TLS minimale déclarée
- **Checklist manuelle** : TrustManager custom, HostnameVerifier, WebView, OkHttp CertificatePinner, Cipher suites

### Onglet 4 — Anomalies
- HTTP cleartext détecté
- Domaines de tunneling (ngrok, localtunnel, requestbin…)
- IPs privées exposées (192.168.x, 10.x, 172.16-31.x)
- IPs publiques brutes (pas de vérification hostname TLS)
- Endpoints test/dev inclus dans l'APK

### Onglet 5 — Rapport IA (Claude)
- **Résumé risques transport** : score /10, top 3 risques, répartition prod/test
- **Recommandations priorisées** : P0/P1/P2/P3 — TLS durci, pinning, HSTS, NSC exemple complet
- Réponses en **streaming temps réel**

---

## 🌐 API Backend (FastAPI)

Documentation interactive : http://localhost:8000/docs

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/health` | Status + vérif clé API |
| POST | `/analyze/text` | Analyse texte (APK strings + proxy + NSC) |
| POST | `/analyze/apk` | Upload APK → extraction automatique |
| POST | `/ai/stream` | Proxy streaming vers Claude API |

---

## 🔧 Extraction APK avancée (optionnel)

Pour extraire les strings d'un APK avant de les coller dans l'outil :

```bash
# Avec apktool (recommandé)
apktool d MonApp.apk -o output/
grep -r "http" output/ --include="*.xml" --include="*.smali" --include="*.json"

# Avec strings (Linux/macOS)
strings MonApp.apk | grep -E "https?://"

# Avec jadx (décompilation Java)
jadx -d output/ MonApp.apk
grep -r "http" output/sources/
```

---

## ⚙️ Variables d'environnement

| Variable | Description | Défaut |
|----------|-------------|--------|
| `ANTHROPIC_API_KEY` | Clé API Claude (requis pour l'IA) | — |

---

## 🛡️ Notes de sécurité

- L'APK uploadé est **traité en mémoire** uniquement, rien n'est stocké sur disque
- La clé API n'est **jamais exposée** au frontend (tout passe par le backend)
- L'outil est conçu pour un usage **défensif** (audit, pentest autorisé)

---

## 📦 Dépendances

**Backend :** `fastapi`, `uvicorn`, `httpx`, `python-multipart`  
**Frontend :** `react`, `vite`, `@vitejs/plugin-react`
