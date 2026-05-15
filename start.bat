@echo off
chcp 65001 > nul
title TLS Posture Analyzer

echo.
echo  ████████╗██╗     ███████╗    ██████╗  ██████╗ ███████╗████████╗██╗   ██╗██████╗ ███████╗
echo  ╚══██╔══╝██║     ██╔════╝    ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝
echo     ██║   ██║     ███████╗    ██████╔╝██║   ██║███████╗   ██║   ██║   ██║██████╔╝█████╗
echo     ██║   ██║     ╚════██║    ██╔═══╝ ██║   ██║╚════██║   ██║   ██║   ██║██╔══██╗██╔══╝
echo     ██║   ███████╗███████║    ██║     ╚██████╔╝███████║   ██║   ╚██████╔╝██║  ██║███████╗
echo     ╚═╝   ╚══════╝╚══════╝    ╚═╝      ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
echo.
echo  Network / TLS Posture Analyzer — Android Security Audit Tool
echo.

set SCRIPT_DIR=%~dp0
set BACKEND_DIR=%SCRIPT_DIR%backend
set FRONTEND_DIR=%SCRIPT_DIR%frontend

:: Load .env if present
if exist "%BACKEND_DIR%\.env" (
  for /f "tokens=1,2 delims==" %%a in (%BACKEND_DIR%\.env) do (
    if not "%%a"=="" set %%a=%%b
  )
)

if "%ANTHROPIC_API_KEY%"=="" (
  echo [WARN] ANTHROPIC_API_KEY non configuree.
  echo        Copiez backend\.env.example vers backend\.env et remplissez la cle.
  echo.
)

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python 3 requis. Installe depuis https://python.org
  pause & exit /b 1
)

:: Check Node
node --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Node.js requis. Installe depuis https://nodejs.org
  pause & exit /b 1
)

:: Install Python deps
echo [*] Installation des dependances Python...
cd "%BACKEND_DIR%"
if not exist "venv" python -m venv venv
call venv\Scripts\activate.bat
pip install -q -r requirements.txt
echo [OK] Backend pret

:: Install Node deps
echo [*] Installation des dependances Node...
cd "%FRONTEND_DIR%"
if not exist "node_modules" npm install --silent
echo [OK] Frontend pret
echo.

:: Start backend
echo [*] Demarrage backend (port 8000)...
cd "%BACKEND_DIR%"
start "TLS-Backend" cmd /k "venv\Scripts\activate.bat && set ANTHROPIC_API_KEY=%ANTHROPIC_API_KEY% && uvicorn main:app --host 0.0.0.0 --port 8000 --reload"

timeout /t 3 /nobreak > nul

:: Start frontend
echo [*] Demarrage frontend (port 5173)...
cd "%FRONTEND_DIR%"
start "TLS-Frontend" cmd /k "npm run dev"

timeout /t 3 /nobreak > nul

echo.
echo ==========================================
echo   OK  App disponible : http://localhost:5173
echo   OK  API docs       : http://localhost:8000/docs
echo ==========================================
echo.
echo Ferme les fenetres "TLS-Backend" et "TLS-Frontend" pour arreter.
pause
