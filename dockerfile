# ============================================================
#  TLS Posture Analyzer — Dockerfile
#  Multi-stage build : frontend (Node) + backend (Python)
# ============================================================

# ── Stage 1 : Build frontend ──────────────────────────────────
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# Copie et install des dépendances npm
COPY frontend/package*.json ./
RUN npm ci --silent

# Build de production Vite
COPY frontend/ ./
RUN npm run build


# ── Stage 2 : Image finale Python ─────────────────────────────
FROM python:3.11-slim

LABEL maintainer="TLS Posture Analyzer"
LABEL description="Android Network Security Audit Tool"

# ── Variables d'environnement ──────────────────────────────────
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    BACKEND_PORT=8000

# ── Dépendances système + jadx + apktool ──────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Runtime Java pour jadx et apktool
    default-jre-headless \
    # Outils réseau (curl pour healthcheck)
    curl \
    wget \
    unzip \
    # Librairies nécessaires pour androguard
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# ── Installation jadx ─────────────────────────────────────────
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip \
        -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip \
    && jadx --version

# ── Installation apktool ──────────────────────────────────────
RUN wget -q https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar \
        -O /opt/apktool.jar \
    && echo '#!/bin/bash\njava -jar /opt/apktool.jar "$@"' > /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool

# ── Dossier de travail backend ────────────────────────────────
WORKDIR /app/backend

# ── Dépendances Python ────────────────────────────────────────
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# ── Code backend ──────────────────────────────────────────────
COPY backend/ ./

# ── Fichier .env (optionnel, peut être monté via volume) ──────
RUN if [ -f .env.example ] && [ ! -f .env ]; then cp .env.example .env; fi

# ── Récupération du build frontend ────────────────────────────
# Servi par le backend FastAPI via StaticFiles
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

# ── Création dossiers runtime ─────────────────────────────────
RUN mkdir -p /app/uploads /app/temp /tmp/jadx_work /tmp/apktool_work \
    && chmod 777 /app/uploads /app/temp /tmp/jadx_work /tmp/apktool_work

# ── Port exposé ───────────────────────────────────────────────
EXPOSE 8000

# ── Healthcheck ───────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# ── Lancement ─────────────────────────────────────────────────
CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--timeout-keep-alive", "300"]