# 🚀 **Guide d'Utilisation Rapide - Après Changements**

## **1. Avant de Démarrer**

### Installation des Dépendances
```bash
cd tls-analyzer
pip install -r backend/requirements.txt
npm install
```

### Configuration de la Clé API Groq

**Option A: Fichier .env (Recommandé)**
```bash
cd backend
echo 'GROQ_API_KEY=gsk_votre_clé' > .env
```

**Option B: Via l'API après démarrage**
```bash
# Démarrer le backend d'abord
# Puis faire:
curl -X POST http://localhost:8000/config/api-key \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "api_key=gsk_votre_clé"
```

---

## **2. Démarrer l'Application**

### Terminal 1 - Backend (FastAPI)
```bash
cd backend
python main.py
# Ou: uvicorn main:app --reload --port 8000
```

**Vérifier le démarrage:**
```bash
curl http://localhost:8000/health
# Réponse: {"status": "ok", "api_key_set": true}
```

### Terminal 2 - Frontend (React/Vite)
```bash
cd frontend
npm run dev
# Accessible sur: http://localhost:5173
```

---

## **3. Utilisation - Analyser un APK**

### Via l'Interface Web
1. Allez sur `http://localhost:5173`
2. Onglet "Entrées" → Upload APK
3. Attendez l'analyse (1-5 min avec Jadx)
4. Consultez les 6 onglets de résultats

### Via cURL - 1 APK
```bash
curl -X POST http://localhost:8000/analyze/apk \
  -F "file=@app.apk"
```

### **NOUVEAU** - Via cURL - Plusieurs APK (Batch)
```bash
curl -X POST http://localhost:8000/analyze/folder \
  -F "files=@app1.apk" \
  -F "files=@app2.apk" \
  -F "files=@app3.apk" \
  > results.json
```

---

## **4. Configurer la Clé API**

### Vérifier le Statut
```bash
curl http://localhost:8000/config/api-key-status
# Réponse: {"configured": true, "api_key_preview": "gsk_7...xLL"}
```

### Changer la Clé (Sans Redémarrer)
```bash
curl -X POST http://localhost:8000/config/api-key \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "api_key=gsk_nouvelle_clé"
# Réponse: {"status": "success", "message": "Clé API Groq configurée"}
```

---

## **5. Décompilation (Optionnel)**

### Si Jadx et Apktool Sont Installés

```bash
# Vérifier les outils disponibles
curl http://localhost:8000/decompile/tools-status

# Décompiler seulement (sans analyse)
curl -X POST http://localhost:8000/decompile/java \
  -F "file=@app.apk" > java_source.json

# Décompilation complète
curl -X POST http://localhost:8000/decompile/full \
  -F "file=@app.apk" > full_analysis.json
```

**Installation des Outils:**
```bash
# Linux
sudo apt install jadx apktool

# macOS
brew install jadx apktool

# Windows (choco)
choco install jadx apktool
```

---

## **6. Endpoints Disponibles**

### Configuration & Santé
```
GET  /health                    # Vérifier le service
POST /config/api-key            # Configurer clé Groq
GET  /config/api-key-status     # Statut de la clé (masqué)
```

### Analyse
```
POST /analyze/text              # Texte brut (debug)
POST /analyze/apk               # 1 APK (Jadx principal)
POST /analyze/folder            # N APK (NEW - Batch)
```

### Décompilation
```
POST /decompile/java            # Jadx → Java source
POST /decompile/smali           # Apktool → Smali
POST /decompile/full            # Complète (3 en 1)
GET  /decompile/tools-status    # Vérifier apktool/jadx
```

### IA
```
POST /ai/stream                 # Groq Llama streaming
```

---

## **7. Exemple Complet - Bash Script**

```bash
#!/bin/bash

# Configuration
BACKEND="http://localhost:8000"
API_KEY="gsk_votre_clé"
APK_DIR="./apk_samples"

# 1. Configurer l'API
echo "📝 Configuration de la clé API..."
curl -X POST "$BACKEND/config/api-key" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "api_key=$API_KEY"

# 2. Vérifier le statut
echo -e "\n✓ Vérification..."
curl "$BACKEND/health"

# 3. Analyser tous les APK d'un dossier
echo -e "\n🔍 Analyse batch..."
files=""
for apk in $APK_DIR/*.apk; do
  files="$files -F files=@$apk"
done

curl -X POST "$BACKEND/analyze/folder" $files > results.json

# 4. Afficher les résultats
echo -e "\n📊 Résultats sauvegardés dans results.json"
cat results.json | python -m json.tool | head -50
```

---

## **8. Résultats - Structure JSON**

### Analyse Single APK
```json
{
  "endpoints": [
    {
      "type": "url",
      "value": "https://api.example.com/v1/users",
      "env": "prod",
      "source": "java_code"
    }
  ],
  "anomalies": [
    {
      "endpoint": "http://dev.example.com",
      "issue": "Cleartext HTTP",
      "severity": "critical"
    }
  ],
  "secrets": [
    {
      "type": "api_key",
      "value": "sk_live_...",
      "location": "com/example/Config.java:42"
    }
  ],
  "tls_checks": [...],
  "stats": {
    "endpoints_count": 12,
    "prod": 8,
    "test": 2,
    "cleartext": 1,
    "anomalies_count": 3,
    "secrets_found": 2
  },
  "decompilation_status": "success"
}
```

### Analyse Batch (/folder)
```json
{
  "total_files": 3,
  "analyzed": 3,
  "failed": 0,
  "apk_results": [
    {
      "filename": "app1.apk",
      "status": "success",
      "endpoints": [...],
      "anomalies": [...],
      "stats": {...}
    },
    {
      "filename": "app2.apk",
      "status": "success",
      ...
    },
    {
      "filename": "app3.apk",
      "status": "error",
      "error": "Fichier corrompu"
    }
  ]
}
```

---

## **9. Troubleshooting**

### Erreur: "GROQ_API_KEY non configurée"
```bash
# Solution 1: Vérifier le fichier .env
cat backend/.env
# Doit contenir: GROQ_API_KEY=gsk_...

# Solution 2: Configurer via l'API
curl -X POST http://localhost:8000/config/api-key \
  -d "api_key=gsk_..."
```

### Erreur: "jadx non installé"
```bash
# Installation:
# Linux: sudo apt install jadx
# macOS: brew install jadx

# Vérifier:
curl http://localhost:8000/decompile/tools-status
# Si "available": false → Installer l'outil
```

### Erreur: "Port 8000 en utilisation"
```bash
# Utiliser un autre port:
uvicorn main:app --port 8001
```

---

## **10. ✨ Résumé des Changements**

| Changement | Impact |
|-----------|--------|
| 🔑 **Config API** | Plus de terminal, fichier `.env` ou API |
| 📁 **Batch APK** | Analyser 10+ APK en 1 requête |
| 🧹 **Code Clean** | -5 debug prints, imports optimisés |
| ⚡ **Perf** | Même vitesse, plus lisible |
| 🔒 **Sécurité** | Clé API masquée, logs propres |

---

## **Besoin d'Aide?**

```bash
# Health check
curl http://localhost:8000/health

# Lister les endpoints disponibles
curl http://localhost:8000/openapi.json | python -m json.tool

# Vérifier les outils
curl http://localhost:8000/decompile/tools-status

# Vérifier l'API Key
curl http://localhost:8000/config/api-key-status
```

**C'est prêt!** 🚀
