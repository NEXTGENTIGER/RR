FROM debian:bullseye-slim

# Installation de Python, des outils de compilation et des dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    gcc \
    make \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    yara \
    exiftool \
    sleuthkit \
    libmagic1 \
    libyara-dev \
    git \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Configuration du répertoire de travail
WORKDIR /app

# Installation des dépendances Python (pycrypto remplacé par pycryptodome)
RUN pip3 install --no-cache-dir \
    requests \
    python-magic \
    yara-python \
    git+https://github.com/graingert/python-clamd.git@master \
    distorm3 \
    pycryptodome \
    pefile \
    capstone \
    volatility3

# Copie des fichiers
COPY forensic_analyzer.py .
COPY rules/malware.yar /app/rules/

# Création des répertoires nécessaires
RUN mkdir -p /app/logs /app/output /app/input /app/rules && \
    chmod -R 755 /app

# Configuration de ClamAV
RUN mkdir -p /var/run/clamav && \
    chown clamav:clamav /var/run/clamav && \
    chmod 750 /var/run/clamav && \
    echo "TCPSocket 3310" >> /etc/clamav/clamd.conf && \
    echo "TCPAddr 0.0.0.0" >> /etc/clamav/clamd.conf && \
    echo "LocalSocket /var/run/clamav/clamd.sock" >> /etc/clamav/clamd.conf && \
    echo "MaxFileSize 100M" >> /etc/clamav/clamd.conf && \
    echo "MaxScanSize 100M" >> /etc/clamav/clamd.conf && \
    freshclam || echo "Freshclam failed" && \
    chown -R clamav:clamav /var/lib/clamav

# Configuration de Volatility
RUN mkdir -p /root/.volatility && \
    echo "plugins=/usr/lib/python3/dist-packages/volatility/plugins" > /root/.volatility/volatilityrc

# Vérification des outils installés
RUN which clamd && \
    which yara && \
    which exiftool && \
    which fls && \
    which volatility3 || echo "Volatility3 not found in PATH"

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC
ENV CLAMD_SOCKET=/var/run/clamav/clamd.sock
ENV CLAMD_TCP=localhost:3310

# Script de vérification de l'environnement
RUN cat << 'EOF' > /app/check_env.sh
#!/bin/sh
echo "Vérification de l'environnement..."
echo "Python: $(python3 --version)"
echo "ClamAV: $(which clamd)"
echo "YARA: $(which yara)"
echo "ExifTool: $(which exiftool)"
echo "Sleuthkit: $(which fls)"
echo "Volatility3: $(which volatility3)"
echo "Répertoires:"
ls -la /app
ls -la /var/run/clamav
EOF

RUN chmod +x /app/check_env.sh

# Commande par défaut
CMD ["sh", "-c", "/app/check_env.sh && clamd & sleep 5 && python3 forensic_analyzer.py /app/input"]
