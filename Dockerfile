# --------------------------------------------------
# ARIA Attacker Container
# --------------------------------------------------

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# --------------------------------------------------
# Install security tools
# --------------------------------------------------

RUN apt-get update && apt-get install -y \
    ffuf \
    nikto \
    sqlmap \
    git \
    curl \
    wget \
    nmap \
    dnsutils \
    net-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------
# Install Python dependencies
# --------------------------------------------------

COPY requirements.txt .

RUN pip install --upgrade pip

RUN pip install --no-cache-dir -r requirements.txt

# --------------------------------------------------
# Copy ARIA source
# --------------------------------------------------

COPY . .

# --------------------------------------------------
# Environment variables
# --------------------------------------------------

ENV DEEPSEEK_API_KEY=""

# --------------------------------------------------
# Launch ARIA
# --------------------------------------------------

CMD ["python", "orchestrator.py"]