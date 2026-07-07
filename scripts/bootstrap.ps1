$ErrorActionPreference = "Stop"

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Starting ARIA Bootstrapper for Windows (PowerShell)  " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

# [1/5 & 2/5] System updates and Python prerequisites
Write-Host "`n[1/5 & 2/5] Verifying Python installation..." -ForegroundColor Yellow
if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Python is not installed or not in your system PATH." -ForegroundColor Red
    Write-Host "Please install Python 3 from python.org or the Microsoft Store." -ForegroundColor Red
    Exit
} else {
    $pythonVersion = python --version
    Write-Host "Found $pythonVersion" -ForegroundColor Green
}

# [3/5] Installing available offensive security tools
Write-Host "`n[3/5] Installing available offensive security tools (Nmap)..." -ForegroundColor Yellow
Write-Host "      Installing Nmap via winget..."
winget install --id Insecure.Nmap -e --accept-package-agreements --accept-source-agreements --silent | Out-Null
Write-Host "      WARNING: ffuf, nikto, and sqlmap do not have native winget packages." -ForegroundColor Magenta
Write-Host "      We recommend running those specific tools via WSL." -ForegroundColor Magenta

# [4/5] Checking and installing Ollama
Write-Host "`n[4/5] Checking and installing Ollama..." -ForegroundColor Yellow
if (-not (Get-Command "ollama" -ErrorAction SilentlyContinue)) {
    Write-Host "      Ollama not found. Installing via winget..."
    winget install --id Ollama.Ollama -e --accept-package-agreements --accept-source-agreements --silent | Out-Null
} else {
    Write-Host "      Ollama is already installed. Skipping..."
}

# [5/5] Setting up Python Virtual Environment
Write-Host "`n[5/5] Setting up Python Virtual Environment..." -ForegroundColor Yellow
$VENV_PATH = "venv"

if (-not (Test-Path "$VENV_PATH")) {
    python -m venv $VENV_PATH
    Write-Host "      Virtual environment created at $VENV_PATH." -ForegroundColor Green
} else {
    Write-Host "      Virtual environment already exists at $VENV_PATH." -ForegroundColor DarkGray
}

# Upgrade pip and install dependencies using the explicit path to the venv executables
Write-Host "      Upgrading pip and installing dependencies..."
& "$VENV_PATH\Scripts\python.exe" -m pip install --upgrade pip
& "$VENV_PATH\Scripts\pip.exe" install chromadb==0.4.24 openai==1.14.0 anthropic==0.21.3 ollama==0.1.7 pydantic==2.6.4 langchain==0.1.13 langgraph==0.0.30

Write-Host "`n=======================================================" -ForegroundColor Cyan
Write-Host "  Bootstrap Complete!                                  " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To begin working on ARIA, run the following commands:"
Write-Host "  1. Activate your environment:  .\$VENV_PATH\Scripts\Activate.ps1"
Write-Host "  2. Start the Ollama server:    (Runs automatically as a Windows background service)"
Write-Host "  3. Pull the LLaMA 3 model:     ollama run llama3"
Write-Host ""