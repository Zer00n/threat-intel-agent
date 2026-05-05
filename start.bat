@echo off
chcp 65001 >nul
title Threat Intel Agent v0.1

echo ==========================================
echo   Threat Intel Agent v0.1
echo ==========================================
echo.

cd /d "%~dp0"

if not exist "venv\Scripts\activate.bat" (
    echo [INFO] Creating virtual environment...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo [INFO] Installing dependencies...
    pip install -r requirements.txt
    echo.
) else (
    call venv\Scripts\activate.bat
)

if not exist ".env" (
    echo [WARN] .env file not found!
    echo [INFO] Copying from .env.example...
    copy .env.example .env
    echo [INFO] Please edit .env to set your ANTHROPIC_API_KEY
    echo.
)

if not exist "data\ti.db" (
    echo [INFO] Initializing database...
    python -m app.scripts.init
    echo.
)

echo ==========================================
echo   Starting server at http://127.0.0.1:8000
echo   Press Ctrl+C to stop
echo ==========================================
echo.

uvicorn app.main:app --host 127.0.0.1 --port 8000

pause
