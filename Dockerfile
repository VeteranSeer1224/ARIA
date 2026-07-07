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
    nikto \
    sqlmap \
    git \
    curl \
    wget \
    nmap \
    dnsutils \
    net-tools \
    perl \
    libwww-perl \
    openssl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------
# Install Python dependencies
# --------------------------------------------------
RUN wget https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz \
    && tar -xzf ffuf_2.1.0_linux_amd64.tar.gz \
    && mv ffuf /usr/local/bin/ \
    && chmod +x /usr/local/bin/ffuf \
    && rm ffuf_2.1.0_linux_amd64.tar.gz


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