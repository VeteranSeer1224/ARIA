#!/bin/bash

# Exit script immediately if any command fails
set -e

echo "======================================================="
echo "  Starting Comprehensive ARIA Bootstrapper for WSL     "
echo "======================================================="

echo ""
echo "[1/5] Updating system package list..."
sudo apt update

echo ""
echo "[2/5] Installing Python prerequisites and base utilities..."
sudo apt install -y python3-pip python3-venv curl wget

echo ""
echo "[3/5] Installing APT-available offensive security & infrastructure tools..."
# Removed crackmapexec as it is not in default Ubuntu/Debian APT repos.
sudo apt install -y nmap ffuf nikto sqlmap docker.io

echo ""
echo "[4/5] Checking and installing Ollama..."
if ! command -v ollama &> /dev/null; then
    echo "      Ollama not found. Installing..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo "      Ollama is already installed. Skipping..."
fi

echo ""
echo "[5/5] Setting up Python Virtual Environment & Dependencies..."
VENV_PATH="venv"

if [ ! -d "$VENV_PATH" ]; then
    python3 -m venv $VENV_PATH
    echo "      Virtual environment created at $VENV_PATH."
else
    echo "      Virtual environment already exists at $VENV_PATH."
fi

# Activate the virtual environment
source $VENV_PATH/bin/activate

# Upgrade pip to avoid installation errors
pip install --upgrade pip

echo ""
echo "Installing unified Python dependencies for P1, P2, P3, and Manya..."
# We use quotes around >= to prevent shell redirection errors
pip install \
    "pydantic>=2.0.0" "openai>=1.0.0" "chromadb>=0.4.0" \
    "pymetasploit3>=1.0.0" \
    "torch>=2.0.0" "transformers>=4.30.0" "peft>=0.4.0" "sentence-transformers>=2.2.0"

echo ""
echo "======================================================="
echo "  Bootstrap Complete!                                  "
echo "======================================================="
echo ""
echo "To begin working on ARIA, run the following commands:"
echo "  1. Activate your environment:  source venv/bin/activate"
echo "  2. Start the Ollama server:    ollama serve &"
echo "  3. Pull the LLaMA 3 model:     ollama run llama3"
echo "  4. Export DeepSeek API Key:    export DEEPSEEK_API_KEY='your_key'"
echo ""
echo "Action Items by Track:"
echo "- P2 (Web): Ensure the Docker service is running to host the local DVWA target."
echo "- P3 (Network): Manually install CrackMapExec (via pipx/source), Metasploit, and BloodHound CE."
echo "======================================================="