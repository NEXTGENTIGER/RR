# Utilisation d'une image Python officielle
FROM python:3.9-slim

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
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
    && rm -rf /var/lib/apt/lists/*

# Configuration du répertoire de travail
WORKDIR /app

# Installation des dépendances Python
RUN pip install --no-cache-dir \
    requests \
    python-magic \
    yara-python \
    git+https://github.com/graingert/python-clamd.git@master

# Copie du script principal
COPY forensic_analyzer.py .

# Création des répertoires nécessaires
RUN mkdir -p /app/logs /app/output /app/input /app/rules

# Configuration de ClamAV
RUN mkdir -p /var/run/clamav && \
    chown clamav:clamav /var/run/clamav && \
    chmod 750 /var/run/clamav && \
    # Configuration du socket ClamAV
    echo "TCPSocket 3310" >> /etc/clamav/clamd.conf && \
    echo "TCPAddr 0.0.0.0" >> /etc/clamav/clamd.conf && \
    echo "LocalSocket /var/run/clamav/clamd.sock" >> /etc/clamav/clamd.conf && \
    # Mise à jour des signatures
    freshclam || true && \
    chown -R clamav:clamav /var/lib/clamav

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

# Commande par défaut
CMD ["python", "forensic_analyzer.py"] 
