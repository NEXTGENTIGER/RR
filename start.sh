#!/bin/bash

# Démarrage du service ClamAV
service clamav-daemon start

# Mise à jour des signatures ClamAV
freshclam

# Attente que le service ClamAV soit prêt
while ! nc -z localhost 3310; do
    echo "En attente du démarrage de ClamAV..."
    sleep 1
done

# Démarrage de l'analyseur
exec python forensic_analyzer.py "$@" 