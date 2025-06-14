# Utilisation d'une image Python officielle
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
RUN mkdir -p /app/logs /app/output /app/input /app/rules

# Configuration de ClamAV
RUN mkdir -p /var/run/clamav && \
    chown clamav:clamav /var/run/clamav && \
    chmod 750 /var/run/clamav && \
    echo "TCPSocket 3310" >> /etc/clamav/clamd.conf && \
    echo "TCPAddr 0.0.0.0" >> /etc/clamav/clamd.conf && \
    echo "LocalSocket /var/run/clamav/clamd.sock" >> /etc/clamav/clamd.conf && \
    freshclam || echo "Freshclam failed" && \
    chown -R clamav:clamav /var/lib/clamav

# Configuration de Volatility
RUN mkdir -p /root/.volatility && \
    echo "plugins=/usr/lib/python3/dist-packages/volatility/plugins" > /root/.volatility/volatilityrc

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

# Commande par défaut qui démarre ClamAV et attend qu'il soit prêt
CMD ["sh", "-c", "service clamav-daemon start && sleep 3 && python forensic_analyzer.py /app/input"] 
