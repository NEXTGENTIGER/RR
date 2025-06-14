#!/bin/bash

# Démarrage du service ClamAV
service clamav-daemon start

# Mise à jour des signatures ClamAV (avec gestion d'erreur)
freshclam || true

# Attente que le service ClamAV soit prêt
echo "En attente du démarrage de ClamAV..."
while ! nc -z localhost 3310; do
    sleep 1
done
echo "ClamAV est prêt"

# Si des arguments sont fournis, exécuter l'analyseur avec ces arguments
if [ $# -gt 0 ]; then
    exec python forensic_analyzer.py "$@"
else
    # Sinon, garder le conteneur en vie
    tail -f /dev/null
fi 