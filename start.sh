#!/bin/bash

# ============================================================
#  TLS Posture Analyzer — Start Script (Linux / macOS)
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "  ████████╗██╗     ███████╗    ██████╗  ██████╗ ███████╗████████╗██╗   ██╗██████╗ ███████╗"
echo "     ██╔══╝██║     ██╔════╝    ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝"
echo "     ██║   ██║     ███████╗    ██████╔╝██║   ██║███████╗   ██║   ██║   ██║██████╔╝█████╗  "
echo "     ██║   ██║     ╚════██║    ██╔═══╝ ██║   ██║╚════██║   ██║   ██║   ██║██╔══██╗██╔══╝  "
echo "     ██║   ███████╗███████║    ██║     ╚██████╔╝███████║   ██║   ╚██████╔╝██║  ██║███████╗"
echo "     ╚═╝   ╚══════╝╚══════╝    ╚═╝      ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝"
echo -e "${NC}"
echo -e "${CYAN}         Android Network Security Audit Tool${NC}"
echo ""

# ── Détection OS ──────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
  Darwin*) PLATFORM="macOS" ;;
  Linux*)  PLATFORM="Linux" ;;
  *)       PLATFORM="Unknown" ;;
esac
echo -e "${GREEN}[+] Plateforme détectée : $PLATFORM${NC}"

# ── Vérification Python ────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo -e "${RED}[!] Python 3 introuvable. Installe-le depuis https://python.org${NC}"
  exit 1
fi
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}[+] Python $PYTHON_VERSION détecté${NC}"

# ── Vérification Node.js ───────────────────────────────────────
if ! command -v node &>/dev/null; then
  echo -e "${RED}[!] Node.js introuvable. Installe-le depuis https://nodejs.org${NC}"
  exit 1
fi
NODE_VERSION=$(node --version)
echo -e "${GREEN}[+] Node.js $NODE_VERSION détecté${NC}"

# ── Vérification outils optionnels ────────────────────────────
echo ""
echo -e "${CYAN}[*] Vérification des outils d'analyse...${NC}"

if command -v jadx &>/dev/null; then
  echo -e "${GREEN}[+] jadx : disponible${NC}"
else
  echo -e "${YELLOW}[~] jadx : non trouvé — la décompilation Java sera limitée${NC}"
  echo -e "${YELLOW}    → Linux : sudo apt install jadx${NC}"
  echo -e "${YELLOW}    → macOS : brew install jadx${NC}"
fi

if command -v apktool &>/dev/null; then
  echo -e "${GREEN}[+] apktool : disponible${NC}"
else
  echo -e "${YELLOW}[~] apktool : non trouvé — le Smali sera indisponible${NC}"
fi

# ── Backend — environnement virtuel ───────────────────────────
echo ""
echo -e "${CYAN}[*] Configuration du backend...${NC}"
cd backend

if [ ! -d ".venv" ]; then
  echo -e "${CYAN}[*] Création de l'environnement virtuel...${NC}"
  python3 -m venv .venv
fi

echo -e "${CYAN}[*] Activation du venv et installation des dépendances...${NC}"
source .venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo -e "${GREEN}[+] Backend prêt${NC}"

# ── Fichier .env ───────────────────────────────────────────────
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  cp .env.example .env
  echo -e "${YELLOW}[~] Fichier .env créé depuis .env.example — configure ta clé Groq si nécessaire${NC}"
fi

# ── Lancement backend en arrière-plan ─────────────────────────
echo -e "${CYAN}[*] Démarrage du backend FastAPI sur le port 8000...${NC}"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload &> ../logs/backend.log &
BACKEND_PID=$!
echo -e "${GREEN}[+] Backend démarré (PID: $BACKEND_PID)${NC}"

# ── Attente que le backend réponde ────────────────────────────
echo -e "${CYAN}[*] Attente du backend...${NC}"
MAX_WAIT=30
COUNT=0
until curl -s http://localhost:8000/health &>/dev/null; do
  sleep 1
  COUNT=$((COUNT + 1))
  if [ $COUNT -ge $MAX_WAIT ]; then
    echo -e "${RED}[!] Le backend n'a pas démarré après ${MAX_WAIT}s. Vérifie logs/backend.log${NC}"
    exit 1
  fi
done
echo -e "${GREEN}[+] Backend opérationnel ✓${NC}"

# ── Frontend ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}[*] Configuration du frontend...${NC}"
cd ../frontend

if [ ! -d "node_modules" ]; then
  echo -e "${CYAN}[*] Installation des packages npm...${NC}"
  npm install -q
fi

echo -e "${CYAN}[*] Démarrage du frontend Vite sur le port 5173...${NC}"
npm run dev &> ../logs/frontend.log &
FRONTEND_PID=$!

# ── Résumé ─────────────────────────────────────────────────────
cd ..
mkdir -p logs
sleep 2
echo ""
echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ TLS Posture Analyzer est lancé !${NC}"
echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo -e "  Frontend  →  ${CYAN}http://localhost:5173${NC}"
echo -e "  Backend   →  ${CYAN}http://localhost:8000${NC}"
echo -e "  API Docs  →  ${CYAN}http://localhost:8000/docs${NC}"
echo -e "  Logs      →  ${CYAN}./logs/${NC}"
echo ""
echo -e "${YELLOW}  Ctrl+C pour arrêter les deux serveurs${NC}"
echo ""

# ── Trap pour cleanup propre ───────────────────────────────────
cleanup() {
  echo ""
  echo -e "${CYAN}[*] Arrêt des serveurs...${NC}"
  kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
  echo -e "${GREEN}[+] Serveurs arrêtés. À bientôt !${NC}"
  exit 0
}
trap cleanup SIGINT SIGTERM

# Garder le script actif
wait