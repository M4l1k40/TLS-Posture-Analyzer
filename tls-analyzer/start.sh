#!/usr/bin/env bash
set -e

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "  ████████╗██╗     ███████╗    ██████╗  ██████╗ ███████╗████████╗██╗   ██╗██████╗ ███████╗"
echo "  ╚══██╔══╝██║     ██╔════╝    ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝"
echo "     ██║   ██║     ███████╗    ██████╔╝██║   ██║███████╗   ██║   ██║   ██║██████╔╝█████╗  "
echo "     ██║   ██║     ╚════██║    ██╔═══╝ ██║   ██║╚════██║   ██║   ██║   ██║██╔══██╗██╔══╝  "
echo "     ██║   ███████╗███████║    ██║     ╚██████╔╝███████║   ██║   ╚██████╔╝██║  ██║███████╗"
echo "     ╚═╝   ╚══════╝╚══════╝    ╚═╝      ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝"
echo -e "${NC}"
echo -e "${BOLD}  Network / TLS Posture Analyzer — Android Security Audit Tool${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"

# ── Check API key ─────────────────────────────────────────────────────────────
if [ -f "$BACKEND_DIR/.env" ]; then
  export $(grep -v '^#' "$BACKEND_DIR/.env" | xargs)
fi

if [ -z "$ANTHROPIC_API_KEY" ]; then
  echo -e "${YELLOW}⚠  ANTHROPIC_API_KEY non configurée.${NC}"
  echo -e "   L'analyse IA sera désactivée. Pour l'activer :"
  echo -e "   ${CYAN}cp backend/.env.example backend/.env && nano backend/.env${NC}"
  echo ""
fi

# ── Check Python ──────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo -e "${RED}✗ Python 3 requis (non trouvé).${NC}"; exit 1
fi

# ── Check Node ────────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  echo -e "${RED}✗ Node.js requis (non trouvé). Installe depuis https://nodejs.org${NC}"; exit 1
fi

# ── Install Python deps ───────────────────────────────────────────────────────
echo -e "${BLUE}▶ Installation des dépendances Python…${NC}"
cd "$BACKEND_DIR"
if [ ! -d "venv" ]; then
  python3 -m venv venv
fi
source venv/bin/activate
pip install -q -r requirements.txt
echo -e "${GREEN}✓ Backend prêt${NC}"

# ── Install Node deps ─────────────────────────────────────────────────────────
echo -e "${BLUE}▶ Installation des dépendances Node…${NC}"
cd "$FRONTEND_DIR"
if [ ! -d "node_modules" ]; then
  npm install --silent
fi
echo -e "${GREEN}✓ Frontend prêt${NC}"
echo ""

# ── Start backend ─────────────────────────────────────────────────────────────
echo -e "${BOLD}🚀 Démarrage du backend (port 8000)…${NC}"
cd "$BACKEND_DIR"
source venv/bin/activate
ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

sleep 2

# ── Start frontend ────────────────────────────────────────────────────────────
echo -e "${BOLD}🚀 Démarrage du frontend (port 5173)…${NC}"
cd "$FRONTEND_DIR"
npm run dev &
FRONTEND_PID=$!

sleep 2
echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✓ App disponible → http://localhost:5173${NC}"
echo -e "${GREEN}${BOLD}  ✓ API docs       → http://localhost:8000/docs${NC}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════${NC}"
echo ""
echo -e "  ${YELLOW}Ctrl+C pour arrêter${NC}"

# ── Cleanup on exit ───────────────────────────────────────────────────────────
trap "echo ''; echo 'Arrêt…'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" INT TERM

wait
