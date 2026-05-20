@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1

:: ============================================================
::  TLS Posture Analyzer — Start Script (Windows)
:: ============================================================

title TLS Posture Analyzer

echo.
echo   ████████╗██╗     ███████╗    ██████╗  ██████╗ ███████╗████████╗██╗   ██╗██████╗ ███████╗
echo      ██╔══╝██║     ██╔════╝    ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝
echo      ██║   ██║     ███████╗    ██████╔╝██║   ██║███████╗   ██║   ██║   ██║██████╔╝█████╗
echo      ██║   ██║     ╚════██║    ██╔═══╝ ██║   ██║╚════██║   ██║   ██║   ██║██╔══██╗██╔══╝
echo      ██║   ███████╗███████║    ██║     ╚██████╔╝███████║   ██║   ╚██████╔╝██║  ██║███████╗
echo      ╚═╝   ╚══════╝╚══════╝    ╚═╝      ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
echo.
echo          Android Network Security Audit Tool
echo.

:: ── Création dossier logs ─────────────────────────────────────
if not exist logs mkdir logs

:: ── Vérification Python ───────────────────────────────────────
echo [*] Vérification de Python...
python --version >nul 2>&1
if errorlevel 1 (
    python3 --version >nul 2>&1
    if errorlevel 1 (
        echo [!] Python introuvable. Installe-le depuis https://python.org
        pause
        exit /b 1
    )
    set PYTHON_CMD=python3
) else (
    set PYTHON_CMD=python
)
for /f "tokens=*" %%i in ('!PYTHON_CMD! --version') do echo [+] %%i detecte

:: ── Vérification Node.js ──────────────────────────────────────
echo [*] Vérification de Node.js...
node --version >nul 2>&1
if errorlevel 1 (
    echo [!] Node.js introuvable. Installe-le depuis https://nodejs.org
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('node --version') do echo [+] Node.js %%i detecte

:: ── Vérification outils optionnels ───────────────────────────
echo.
echo [*] Vérification des outils d'analyse...

jadx --version >nul 2>&1
if errorlevel 1 (
    echo [~] jadx : non trouve ^(decompilation Java limitee^)
    echo     ^-^> Installe depuis https://github.com/skylot/jadx/releases
) else (
    echo [+] jadx : disponible
)

apktool --version >nul 2>&1
if errorlevel 1 (
    echo [~] apktool : non trouve ^(Smali indisponible^)
) else (
    echo [+] apktool : disponible
)

:: ── Backend — environnement virtuel ──────────────────────────
echo.
echo [*] Configuration du backend...
cd backend

if not exist .venv (
    echo [*] Creation de l'environnement virtuel...
    !PYTHON_CMD! -m venv .venv
    if errorlevel 1 (
        echo [!] Echec creation venv
        pause
        exit /b 1
    )
)

echo [*] Activation du venv et installation des dependances...
call .venv\Scripts\activate.bat

python -m pip install --upgrade pip -q
pip install -r requirements.txt -q
if errorlevel 1 (
    echo [!] Echec installation des dependances backend
    pause
    exit /b 1
)
echo [+] Backend pret

:: ── Fichier .env ──────────────────────────────────────────────
if not exist .env (
    if exist .env.example (
        copy .env.example .env >nul
        echo [~] Fichier .env cree depuis .env.example
        echo     Configure ta cle Groq si necessaire : GROQ_API_KEY=gsk_...
    )
)

:: ── Lancement backend ─────────────────────────────────────────
echo [*] Demarrage du backend FastAPI sur le port 8000...
start "TLS-Backend" /min cmd /c "call .venv\Scripts\activate.bat && uvicorn main:app --host 0.0.0.0 --port 8000 --reload > ..\logs\backend.log 2>&1"

:: ── Attente backend ───────────────────────────────────────────
echo [*] Attente du backend...
set /a COUNT=0
:WAIT_BACKEND
timeout /t 1 /nobreak >nul
curl -s http://localhost:8000/health >nul 2>&1
if not errorlevel 1 goto BACKEND_OK
set /a COUNT=COUNT+1
if !COUNT! GEQ 30 (
    echo [!] Le backend n'a pas demarre apres 30s
    echo     Consulte logs\backend.log pour le detail
    pause
    exit /b 1
)
goto WAIT_BACKEND

:BACKEND_OK
echo [+] Backend operationnel !

:: ── Frontend ──────────────────────────────────────────────────
echo.
echo [*] Configuration du frontend...
cd ..\frontend

if not exist node_modules (
    echo [*] Installation des packages npm...
    npm install
    if errorlevel 1 (
        echo [!] Echec installation npm
        pause
        exit /b 1
    )
)

echo [*] Demarrage du frontend Vite sur le port 5173...
start "TLS-Frontend" /min cmd /c "npm run dev > ..\logs\frontend.log 2>&1"

:: ── Ouvrir le navigateur ──────────────────────────────────────
cd ..
timeout /t 3 /nobreak >nul
echo [*] Ouverture du navigateur...
start http://localhost:5173

:: ── Résumé ────────────────────────────────────────────────────
echo.
echo ============================================
echo   TLS Posture Analyzer est lance !
echo ============================================
echo   Frontend  -^>  http://localhost:5173
echo   Backend   -^>  http://localhost:8000
echo   API Docs  -^>  http://localhost:8000/docs
echo   Logs      -^>  .\logs\
echo.
echo   Ferme les fenetres "TLS-Backend" et
echo   "TLS-Frontend" pour arreter les serveurs.
echo ============================================
echo.
pause