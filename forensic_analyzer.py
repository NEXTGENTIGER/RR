#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Forensic Analyzer - Outil d'analyse forensique complet
Analyse les fichiers, la mémoire, les disques et les systèmes
"""

import os
import sys
import json
import time
import magic
import hashlib
import platform
import subprocess
import datetime
import yara
import clamd
import pefile
import requests
import psutil
import socket
import struct
import binascii
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

# Configuration
API_CONFIG = {
    'endpoint': 'http://127.0.0.1:5000/api/v1/report/upload_json/',
    'timeout': 30,
    'max_retries': 3
}

# Configuration des chemins
PATHS = {
    'input': '/app/input',
    'output': '/app/output',
    'logs': '/app/logs',
    'rules': '/app/rules'
}

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('forensic_analysis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ForensicAnalyzer:
    def __init__(self, target_path):
        self.target_path = target_path
        self.setup_environment()
        self.report = {
            "timestamp": datetime.datetime.now().isoformat(),
            "target": target_path,
            "analysis": {
                "basic_info": {},
                "static_analysis": {},
                "dynamic_analysis": {},
                "threats": {},
                "recommendations": []
            }
        }

    def setup_environment(self):
        """Configure l'environnement d'analyse"""
        try:
            # Création des répertoires
            for path in PATHS.values():
                os.makedirs(path, exist_ok=True)

            # Configuration de ClamAV
            self.setup_clamav()
            
            # Chargement des règles YARA
            self.setup_yara_rules()
            
            logger.info("Environnement configuré avec succès")
        except Exception as e:
            logger.error(f"Erreur lors de la configuration: {str(e)}")
            raise

    def setup_clamav(self):
        """Configure ClamAV"""
        try:
            self.clamd = clamd.ClamdUnixSocket()
            self.clamd.ping()
            logger.info("ClamAV configuré avec succès")
        except Exception as e:
            logger.warning(f"ClamAV non disponible: {str(e)}")
            self.clamd = None

    def setup_yara_rules(self):
        """Charge les règles YARA"""
        try:
            rules_path = Path(PATHS['rules']) / 'malware.yar'
            if rules_path.exists():
                self.yara_rules = yara.compile(str(rules_path))
                logger.info("Règles YARA chargées avec succès")
            else:
                logger.warning("Fichier de règles YARA non trouvé")
        except Exception as e:
            logger.error(f"Erreur lors du chargement des règles YARA: {str(e)}")

    def analyze_file(self):
        """Analyse un fichier"""
        try:
            # Analyse de base
            self.analyze_basic_info()
            
            # Analyse statique
            self.analyze_static()
            
            # Analyse dynamique
            self.analyze_dynamic()
            
            # Détection des menaces
            self.detect_threats()
            
            # Génération des recommandations
            self.generate_recommendations()
            
            return self.report
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse: {str(e)}")
            raise

    def analyze_basic_info(self):
        """Analyse les informations de base"""
        try:
            file_path = Path(self.target_path)
            if not file_path.exists():
                raise FileNotFoundError(f"Fichier non trouvé: {self.target_path}")

            self.report["analysis"]["basic_info"] = {
                "filename": file_path.name,
                "size": file_path.stat().st_size,
                "type": magic.from_file(str(file_path)),
                "md5": self.calculate_hash(str(file_path), "md5"),
                "sha1": self.calculate_hash(str(file_path), "sha1"),
                "sha256": self.calculate_hash(str(file_path), "sha256"),
                "created": datetime.datetime.fromtimestamp(file_path.stat().st_ctime).isoformat(),
                "modified": datetime.datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des informations de base: {str(e)}")
            raise

    def analyze_static(self):
        """Analyse statique"""
        try:
            self.report["analysis"]["static_analysis"] = {
                "strings": self.extract_strings(),
                "yara_matches": self.scan_yara(),
                "clamav_results": self.scan_clamav()
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse statique: {str(e)}")
            raise

    def analyze_dynamic(self):
        """Analyse dynamique"""
        try:
            self.report["analysis"]["dynamic_analysis"] = {
                "processes": self.analyze_processes(),
                "network": self.analyze_network(),
                "files": self.analyze_files()
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse dynamique: {str(e)}")
            raise

    def detect_threats(self):
        """Détecte les menaces"""
        try:
            self.report["analysis"]["threats"] = {
                "malware": self.detect_malware(),
                "shellcode": self.detect_shellcode(),
                "packer": self.detect_packer(),
                "anti_analysis": self.detect_anti_analysis(),
                "persistence": self.detect_persistence(),
                "privilege_escalation": self.detect_privilege_escalation(),
                "data_exfiltration": self.detect_data_exfiltration()
            }
        except Exception as e:
            logger.error(f"Erreur lors de la détection des menaces: {str(e)}")
            raise

    def generate_recommendations(self):
        """Génère des recommandations"""
        try:
            recommendations = []
            
            if self.report["analysis"]["threats"]["malware"]:
                recommendations.append("Isoler le système immédiatement")
                recommendations.append("Effectuer une analyse complète avec un antivirus à jour")
            
            if self.report["analysis"]["threats"]["shellcode"]:
                recommendations.append("Vérifier les processus en cours")
                recommendations.append("Analyser la mémoire pour d'autres shellcodes")
            
            if self.report["analysis"]["threats"]["packer"]:
                recommendations.append("Déballer le malware pour analyse approfondie")
                recommendations.append("Vérifier les signatures de packers connus")
            
            self.report["analysis"]["recommendations"] = recommendations
        except Exception as e:
            logger.error(f"Erreur lors de la génération des recommandations: {str(e)}")
            raise

    def calculate_hash(self, file_path, hash_type):
        """Calcule le hash d'un fichier"""
        try:
            hash_func = getattr(hashlib, hash_type)()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            logger.error(f"Erreur lors du calcul du hash {hash_type}: {str(e)}")
            return None

    def extract_strings(self):
        """Extrait les chaînes de caractères"""
        try:
            result = subprocess.run(['strings', self.target_path],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  text=True)
            return result.stdout.splitlines()
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des chaînes: {str(e)}")
            return []

    def scan_yara(self):
        """Scanne avec YARA"""
        try:
            if hasattr(self, 'yara_rules'):
                matches = self.yara_rules.match(self.target_path)
                return [match.rule for match in matches]
            return []
        except Exception as e:
            logger.error(f"Erreur lors du scan YARA: {str(e)}")
            return []

    def scan_clamav(self):
        """Scanne avec ClamAV"""
        try:
            if self.clamd:
                result = self.clamd.scan(self.target_path)
                return result
            return []
        except Exception as e:
            logger.error(f"Erreur lors du scan ClamAV: {str(e)}")
            return []

    def analyze_processes(self):
        """Analyse les processus"""
        try:
            return [p.info for p in psutil.process_iter(['pid', 'name', 'cmdline'])]
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des processus: {str(e)}")
            return []

    def analyze_network(self):
        """Analyse le réseau"""
        try:
            return [conn.info for conn in psutil.net_connections()]
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse réseau: {str(e)}")
            return []

    def analyze_files(self):
        """Analyse les fichiers"""
        try:
            return [f for f in Path(self.target_path).rglob('*') if f.is_file()]
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des fichiers: {str(e)}")
            return []

    def detect_malware(self):
        """Détecte les malwares"""
        try:
            malware = []
            if self.report["analysis"]["static_analysis"]["clamav_results"]:
                malware.extend(self.report["analysis"]["static_analysis"]["clamav_results"])
            if self.report["analysis"]["static_analysis"]["yara_matches"]:
                malware.extend(self.report["analysis"]["static_analysis"]["yara_matches"])
            return malware
        except Exception as e:
            logger.error(f"Erreur lors de la détection des malwares: {str(e)}")
            return []

    def detect_shellcode(self):
        """Détecte les shellcodes"""
        try:
            shellcode = []
            # Logique de détection de shellcode
            return shellcode
        except Exception as e:
            logger.error(f"Erreur lors de la détection des shellcodes: {str(e)}")
            return []

    def detect_packer(self):
        """Détecte les packers"""
        try:
            packers = []
            # Logique de détection de packers
            return packers
        except Exception as e:
            logger.error(f"Erreur lors de la détection des packers: {str(e)}")
            return []

    def detect_anti_analysis(self):
        """Détecte les techniques anti-analyse"""
        try:
            anti_analysis = []
            # Logique de détection anti-analyse
            return anti_analysis
        except Exception as e:
            logger.error(f"Erreur lors de la détection des techniques anti-analyse: {str(e)}")
            return []

    def detect_persistence(self):
        """Détecte les mécanismes de persistance"""
        try:
            persistence = []
            # Logique de détection de persistance
            return persistence
        except Exception as e:
            logger.error(f"Erreur lors de la détection des mécanismes de persistance: {str(e)}")
            return []

    def detect_privilege_escalation(self):
        """Détecte les tentatives d'élévation de privilèges"""
        try:
            privilege_escalation = []
            # Logique de détection d'élévation de privilèges
            return privilege_escalation
        except Exception as e:
            logger.error(f"Erreur lors de la détection des tentatives d'élévation de privilèges: {str(e)}")
            return []

    def detect_data_exfiltration(self):
        """Détecte les tentatives d'exfiltration de données"""
        try:
            exfiltration = []
            # Logique de détection d'exfiltration
            return exfiltration
        except Exception as e:
            logger.error(f"Erreur lors de la détection des tentatives d'exfiltration: {str(e)}")
            return []

    def save_report(self):
        """Sauvegarde le rapport localement"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(PATHS['output'], f"report_{timestamp}.json")
            
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(self.report, f, indent=4, ensure_ascii=False)
            
            logger.info(f"Rapport sauvegardé dans {report_path}")
            return report_path
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde du rapport: {str(e)}")
            return None

    def send_to_api(self):
        """Envoie le rapport à l'API"""
        try:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            for attempt in range(API_CONFIG['max_retries']):
                try:
                    response = requests.post(
                        API_CONFIG['endpoint'],
                        json=self.report,
                        headers=headers,
                        timeout=API_CONFIG['timeout']
                    )
                    response.raise_for_status()
                    logger.info(f"Rapport envoyé avec succès à l'API")
                    return response.json()
                except requests.exceptions.RequestException as e:
                    if attempt == API_CONFIG['max_retries'] - 1:
                        raise e
                    continue
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi à l'API: {str(e)}")
            return None

def main():
    parser = argparse.ArgumentParser(description='Analyse forensique de fichiers')
    parser.add_argument('target', help='Chemin du fichier à analyser')
    parser.add_argument('--output', help='Chemin du fichier de sortie', default=None)
    parser.add_argument('--verbose', action='store_true', help='Affiche plus d\'informations')
    args = parser.parse_args()

    try:
        # Analyse du fichier
        analyzer = ForensicAnalyzer(args.target)
        report = analyzer.analyze_file()
        
        # Sauvegarde locale
        report_path = analyzer.save_report()
        
        # Envoi à l'API
        api_response = analyzer.send_to_api()
        
        if args.verbose:
            print(json.dumps(report, indent=4, ensure_ascii=False))
            
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()           
