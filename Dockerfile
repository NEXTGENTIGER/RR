FROM python:3.9-slim

# Installation des dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    yara \
    exiftool \
    sleuthkit \
    libmagic1 \
    python3-dev \
    libyara-dev \
    git \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Configuration du répertoire de travail
WORKDIR /app

# Installation des dépendances Python
RUN pip install --no-cache-dir \
    requests \
    python-magic \
    yara-python \
    git+https://github.com/graingert/python-clamd.git@master \
    distorm3 \
    pycrypto \
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
RUN echo '#!/bin/sh\n\
echo "Vérification de l\'environnement..."\n\
echo "ClamAV: $(which clamd)"\n\
echo "YARA: $(which yara)"\n\
echo "ExifTool: $(which exiftool)"\n\
echo "Sleuthkit: $(which fls)"\n\
echo "Volatility3: $(which volatility3)"\n\
echo "Répertoires:"\n\
ls -la /app\n\
ls -la /var/run/clamav\n' > /app/check_env.sh && chmod +x /app/check_env.sh

# Commande par défaut
CMD ["sh", "-c", "/app/check_env.sh && service clamav-daemon start && sleep 3 && python forensic_analyzer.py /app/input"]
