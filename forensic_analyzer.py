#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Forensic Analyzer - Outil d'analyse forensique autonome
Analyse les fichiers, la mémoire et les systèmes sans dépendances externes
"""

import os
import sys
import json
import time
import hashlib
import platform
import subprocess
import datetime
import socket
import struct
import binascii
import logging
import argparse
import re
import base64
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from urllib import request
from urllib.error import URLError

# Configuration
API_CONFIG = {
    'endpoint': 'http://127.0.0.1:5000/api/v1/report/upload_json/',
    'timeout': 30,
    'max_retries': 3
}

# Configuration des chemins
PATHS = {
    'input': './input',
    'output': './output',
    'logs': './logs',
    'rules': './rules'
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
            
            logger.info("Environnement configuré avec succès")
        except Exception as e:
            logger.error(f"Erreur lors de la configuration: {str(e)}")
            raise

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

            # Détection du type MIME basique
            mime_type = self.detect_mime_type(str(file_path))

            self.report["analysis"]["basic_info"] = {
                "filename": file_path.name,
                "size": file_path.stat().st_size,
                "type": mime_type,
                "md5": self.calculate_hash(str(file_path), "md5"),
                "sha1": self.calculate_hash(str(file_path), "sha1"),
                "sha256": self.calculate_hash(str(file_path), "sha256"),
                "created": datetime.datetime.fromtimestamp(file_path.stat().st_ctime).isoformat(),
                "modified": datetime.datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des informations de base: {str(e)}")
            raise

    def detect_mime_type(self, file_path):
        """Détecte le type MIME d'un fichier"""
        try:
            # Lecture des premiers octets du fichier
            with open(file_path, 'rb') as f:
                header = f.read(2048)
            
            # Signatures de fichiers courantes
            signatures = {
                b'PK\x03\x04': 'application/zip',
                b'\x7fELF': 'application/x-executable',
                b'MZ': 'application/x-dosexec',
                b'%PDF': 'application/pdf',
                b'\x89PNG': 'image/png',
                b'\xff\xd8\xff': 'image/jpeg',
                b'GIF87a': 'image/gif',
                b'GIF89a': 'image/gif'
            }
            
            for sig, mime in signatures.items():
                if header.startswith(sig):
                    return mime
            
            return 'application/octet-stream'
        except Exception:
            return 'application/octet-stream'

    def analyze_static(self):
        """Analyse statique"""
        try:
            self.report["analysis"]["static_analysis"] = {
                "strings": self.extract_strings(),
                "entropy": self.calculate_entropy(),
                "patterns": self.detect_patterns()
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse statique: {str(e)}")
            raise

    def analyze_dynamic(self):
        """Analyse dynamique"""
        try:
            self.report["analysis"]["dynamic_analysis"] = {
                "system_info": self.get_system_info(),
                "network_info": self.get_network_info(),
                "file_operations": self.analyze_file_operations()
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse dynamique: {str(e)}")
            raise

    def calculate_entropy(self):
        """Calcule l'entropie du fichier"""
        try:
            with open(self.target_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0
            
            entropy = 0
            for x in range(256):
                p_x = data.count(bytes([x])) / len(data)
                if p_x > 0:
                    entropy += -p_x * math.log2(p_x)
            
            return entropy
        except Exception as e:
            logger.error(f"Erreur lors du calcul de l'entropie: {str(e)}")
            return 0

    def detect_patterns(self):
        """Détecte les motifs suspects"""
        patterns = {
            'ip_addresses': self.find_ip_addresses(),
            'urls': self.find_urls(),
            'base64': self.find_base64(),
            'hex_patterns': self.find_hex_patterns()
        }
        return patterns

    def find_ip_addresses(self):
        """Trouve les adresses IP"""
        try:
            with open(self.target_path, 'rb') as f:
                content = f.read().decode('utf-8', errors='ignore')
            
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            return re.findall(ip_pattern, content)
        except Exception:
            return []

    def find_urls(self):
        """Trouve les URLs"""
        try:
            with open(self.target_path, 'rb') as f:
                content = f.read().decode('utf-8', errors='ignore')
            
            url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
            return re.findall(url_pattern, content)
        except Exception:
            return []

    def find_base64(self):
        """Trouve les chaînes en base64"""
        try:
            with open(self.target_path, 'rb') as f:
                content = f.read().decode('utf-8', errors='ignore')
            
            base64_pattern = r'[A-Za-z0-9+/]{32,}={0,2}'
            return re.findall(base64_pattern, content)
        except Exception:
            return []

    def find_hex_patterns(self):
        """Trouve les motifs hexadécimaux"""
        try:
            with open(self.target_path, 'rb') as f:
                content = f.read()
            
            patterns = []
            for i in range(len(content) - 8):
                chunk = content[i:i+8]
                if all(c in b'0123456789ABCDEFabcdef' for c in chunk):
                    patterns.append(binascii.hexlify(chunk).decode())
            
            return patterns
        except Exception:
            return []

    def get_system_info(self):
        """Obtient les informations système"""
        return {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'processor': platform.processor(),
            'hostname': socket.gethostname(),
            'ip_address': socket.gethostbyname(socket.gethostname())
        }

    def get_network_info(self):
        """Obtient les informations réseau"""
        try:
            return {
                'hostname': socket.gethostname(),
                'ip_address': socket.gethostbyname(socket.gethostname()),
                'connections': self.get_active_connections()
            }
        except Exception:
            return {}

    def get_active_connections(self):
        """Obtient les connexions actives"""
        try:
            if platform.system() == 'Windows':
                netstat = subprocess.check_output(['netstat', '-an'], text=True)
            else:
                netstat = subprocess.check_output(['netstat', '-tunlp'], text=True)
            return netstat.splitlines()
        except Exception:
            return []

    def analyze_file_operations(self):
        """Analyse les opérations sur les fichiers"""
        try:
            file_path = Path(self.target_path)
            return {
                'permissions': oct(file_path.stat().st_mode)[-3:],
                'owner': file_path.owner() if hasattr(file_path, 'owner') else 'N/A',
                'group': file_path.group() if hasattr(file_path, 'group') else 'N/A',
                'is_symlink': file_path.is_symlink(),
                'is_hidden': file_path.name.startswith('.')
            }
        except Exception:
            return {}

    def detect_threats(self):
        """Détecte les menaces"""
        try:
            self.report["analysis"]["threats"] = {
                "suspicious_patterns": self.detect_suspicious_patterns(),
                "encrypted_content": self.detect_encryption(),
                "obfuscated_code": self.detect_obfuscation(),
                "network_indicators": self.detect_network_indicators()
            }
        except Exception as e:
            logger.error(f"Erreur lors de la détection des menaces: {str(e)}")
            raise

    def detect_suspicious_patterns(self):
        """Détecte les motifs suspects"""
        patterns = []
        try:
            with open(self.target_path, 'rb') as f:
                content = f.read().decode('utf-8', errors='ignore')
            
            # Recherche de motifs suspects
            suspicious = [
                'cmd.exe', 'powershell', 'wget', 'curl', 'download',
                'http://', 'https://', 'ftp://', 'net user', 'net group'
            ]
            
            for pattern in suspicious:
                if pattern.lower() in content.lower():
                    patterns.append(pattern)
            
            return patterns
        except Exception:
            return []

    def detect_encryption(self):
        """Détecte le contenu chiffré"""
        try:
            entropy = self.calculate_entropy()
            return {
                'high_entropy': entropy > 7.0,
                'entropy_value': entropy
            }
        except Exception:
            return {'high_entropy': False, 'entropy_value': 0}

    def detect_obfuscation(self):
        """Détecte le code obfusqué"""
        try:
            with open(self.target_path, 'rb') as f:
                content = f.read().decode('utf-8', errors='ignore')
            
            indicators = {
                'base64_encoded': len(self.find_base64()) > 0,
                'hex_encoded': len(self.find_hex_patterns()) > 0,
                'suspicious_length': len(content) > 1000000
            }
            
            return indicators
        except Exception:
            return {}

    def detect_network_indicators(self):
        """Détecte les indicateurs réseau"""
        return {
            'ip_addresses': self.find_ip_addresses(),
            'urls': self.find_urls()
        }

    def generate_recommendations(self):
        """Génère des recommandations"""
        try:
            recommendations = []
            threats = self.report["analysis"]["threats"]
            
            if threats["suspicious_patterns"]:
                recommendations.append("Fichier contient des motifs suspects - Analyse approfondie recommandée")
            
            if threats["encrypted_content"]["high_entropy"]:
                recommendations.append("Contenu potentiellement chiffré détecté - Vérification de l'intégrité recommandée")
            
            if threats["obfuscated_code"]["base64_encoded"] or threats["obfuscated_code"]["hex_encoded"]:
                recommendations.append("Code potentiellement obfusqué détecté - Analyse statique approfondie recommandée")
            
            if threats["network_indicators"]["ip_addresses"] or threats["network_indicators"]["urls"]:
                recommendations.append("Indicateurs réseau détectés - Analyse du trafic réseau recommandée")
            
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
            with open(self.target_path, 'rb') as f:
                content = f.read()
            
            # Extraction des chaînes ASCII
            strings = []
            current_string = ''
            
            for byte in content:
                if 32 <= byte <= 126:  # Caractères ASCII imprimables
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:  # Minimum 4 caractères
                        strings.append(current_string)
                    current_string = ''
            
            if len(current_string) >= 4:
                strings.append(current_string)
            
            return strings
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des chaînes: {str(e)}")
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
            
            data = json.dumps(self.report).encode('utf-8')
            req = request.Request(
                API_CONFIG['endpoint'],
                data=data,
                headers=headers,
                method='POST'
            )
            
            for attempt in range(API_CONFIG['max_retries']):
                try:
                    with request.urlopen(req, timeout=API_CONFIG['timeout']) as response:
                        logger.info(f"Rapport envoyé avec succès à l'API")
                        return json.loads(response.read().decode())
                except URLError as e:
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
