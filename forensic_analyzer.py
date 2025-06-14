#!/usr/bin/env python3
import os
import json
import hashlib
import subprocess
import requests
import magic
import yara
import tempfile
import shutil
import logging
import zipfile
import platform
import sys
from datetime import datetime
from typing import Dict, Any, Optional, List, Set
from json import JSONEncoder
from pathlib import Path

# Configuration de l'API
API_CONFIG = {
    'endpoint': os.getenv('API_ENDPOINT', 'http://127.0.0.1:5000/api/v1/report/upload_json/'),
    'timeout': int(os.getenv('API_TIMEOUT', '30')),
    'retries': int(os.getenv('API_RETRIES', '3')),
    'enabled': os.getenv('API_ENABLED', 'true').lower() == 'true'
}

# Règles YARA de base
YARA_RULES = """
rule Suspicious_Executable {
    meta:
        description = "Détecte les fichiers exécutables suspects"
        severity = "HIGH"
    strings:
        $mz = "MZ"
        $pe = "PE"
        $exe = ".exe"
    condition:
        $mz at 0 and $pe and $exe
}

rule Malicious_Shellcode {
    meta:
        description = "Détecte les shellcodes malveillants"
        severity = "HIGH"
    strings:
        $shellcode1 = { 90 90 90 90 90 90 90 90 }  // NOP sled
        $shellcode2 = { 68 ?? ?? ?? ?? C3 }        // PUSH + RET
    condition:
        any of them
}

rule Suspicious_Strings {
    meta:
        description = "Détecte les chaînes de caractères suspectes"
        severity = "MEDIUM"
    strings:
        $cmd = "cmd.exe" nocase
        $powershell = "powershell" nocase
        $wget = "wget" nocase
        $curl = "curl" nocase
        $download = "download" nocase
    condition:
        2 of them
}

rule Suspicious_IP {
    meta:
        description = "Détecte les adresses IP suspectes"
        severity = "MEDIUM"
    strings:
        $ip = /(?:[0-9]{1,3}\.){3}[0-9]{1,3}/
    condition:
        $ip
}
"""

# Détection du système d'exploitation
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

# Configuration des logs
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = logging.INFO
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "forensic_analyzer.log"

# Extensions de fichiers
MEMORY_EXTENSIONS = {'.dmp', '.mem', '.raw', '.img', '.dump'}
DISK_EXTENSIONS = {'.dd', '.img', '.raw', '.vmdk', '.vhd', '.vhdx'}

# Niveaux de risque
RISK_LEVELS = {
    'LOW': 0,
    'MEDIUM': 1,
    'HIGH': 2,
    'CRITICAL': 3
}

# Configuration des outils selon l'OS
TOOLS = {
    'clamav': {
        'commands': {
            'Windows': ['clamd.exe', 'clamdscan.exe'],
            'Linux': ['clamd', 'clamdscan'],
            'Darwin': ['clamd', 'clamdscan']
        },
        'required': True
    },
    'yara': {
        'commands': {
            'Windows': ['yara.exe'],
            'Linux': ['yara'],
            'Darwin': ['yara']
        },
        'required': True
    },
    'volatility': {
        'commands': {
            'Windows': ['volatility3.exe', 'vol.py', 'volatility.exe'],
            'Linux': ['volatility3', 'vol.py', 'volatility'],
            'Darwin': ['volatility3', 'vol.py', 'volatility']
        },
        'required': False
    },
    'sleuthkit': {
        'commands': {
            'Windows': ['fls.exe'],
            'Linux': ['fls'],
            'Darwin': ['fls']
        },
        'required': False
    },
    'exiftool': {
        'commands': {
            'Windows': ['exiftool.exe'],
            'Linux': ['exiftool'],
            'Darwin': ['exiftool']
        },
        'required': True
    }
}

class DateTimeEncoder(JSONEncoder):
    """Encodeur personnalisé pour gérer les objets datetime dans le JSON."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class ForensicAnalyzer:
    def __init__(self, file_path, api_endpoint=None):
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.api_endpoint = api_endpoint or API_CONFIG['endpoint']
        self.output_dir = "/app/output"
        self.log_dir = "/app/logs"
        self.rules_dir = "/app/rules"
        self.setup_directories()
        self.setup_logging()
        self.setup_yara_rules()
        
        # Initialisation de ClamAV
        self.clamd_client = None
        try:
            import clamd
            self.clamd_client = clamd.ClamdUnixSocket()
            # Test de la connexion
            self.clamd_client.ping()
            print("ClamAV est connecté et prêt")
        except Exception as e:
            print(f"Warning: ClamAV not available: {e}")
            self.clamd_client = None

    def setup_directories(self):
        """Crée les répertoires nécessaires."""
        for directory in [self.output_dir, self.log_dir, self.rules_dir]:
            os.makedirs(directory, exist_ok=True)

    def setup_logging(self):
        """Configure la journalisation."""
        self.log_file = os.path.join(self.log_dir, f"forensic_analyzer_{self.timestamp}.log")
        with open(self.log_file, 'w') as f:
            f.write(f"=== Début de l'analyse: {self.timestamp} ===\n")

    def log(self, message):
        """Écrit un message dans le fichier de log."""
        with open(self.log_file, 'a') as f:
            f.write(f"{datetime.now()}: {message}\n")

    def execute_command(self, command):
        """Exécute une commande et retourne sa sortie."""
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None
            }
        except Exception as e:
            return {
                "success": False,
                "output": None,
                "error": str(e)
            }

    def get_basic_metadata(self):
        """Récupère les métadonnées de base du fichier."""
        try:
            file_stats = os.stat(self.file_path)
            return {
                "nom": self.file_name,
                "taille": file_stats.st_size,
                "date_creation": datetime.fromtimestamp(file_stats.st_ctime).isoformat(),
                "date_modification": datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                "type_mime": magic.from_file(self.file_path, mime=True)
            }
        except Exception as e:
            self.log(f"Erreur lors de la récupération des métadonnées: {str(e)}")
            return {}

    def scan_clamav(self):
        """Analyse le fichier avec ClamAV."""
        if self.clamd_client is None:
            return {"status": "ClamAV scanning disabled - daemon not available"}
        
        try:
            result = self.clamd_client.scan(self.file_path)
            return result.get(self.file_path, {})
        except Exception as e:
            self.log(f"Erreur lors de l'analyse ClamAV: {str(e)}")
            return {"error": str(e)}

    def setup_yara_rules(self):
        """Configure les règles YARA."""
        try:
            # Compilation des règles intégrées
            self.yara_rules = yara.compile(source=YARA_RULES)
            print("Règles YARA chargées avec succès")
        except Exception as e:
            print(f"Erreur lors du chargement des règles YARA: {e}")
            self.yara_rules = None

    def scan_yara(self):
        """Analyse le fichier avec YARA."""
        try:
            if self.yara_rules:
                matches = self.yara_rules.match(self.file_path)
                return [{
                    'rule': match.rule,
                    'meta': match.meta,
                    'strings': [str(s) for s in match.strings]
                } for match in matches]
            return []
        except Exception as e:
            self.log(f"Erreur lors de l'analyse YARA: {str(e)}")
            return []

    def get_exif_data(self):
        """Récupère les métadonnées EXIF avec exiftool."""
        return self.execute_command(['exiftool', '-j', self.file_path])

    def analyze_with_sleuthkit(self):
        """Analyse avec SleuthKit."""
        results = {}
        
        # Vérification si c'est une image disque
        if any(self.file_path.lower().endswith(ext) for ext in DISK_EXTENSIONS):
            try:
                # Analyse avec fls
                fls_cmd = ['fls', '-r', self.file_path]
                fls_result = self.execute_command(fls_cmd)
                results['fls'] = fls_result

                # Analyse avec mmls
                mmls_cmd = ['mmls', self.file_path]
                mmls_result = self.execute_command(mmls_cmd)
                results['mmls'] = mmls_result
            except Exception as e:
                self.log(f"Erreur lors de l'analyse SleuthKit: {str(e)}")
                results['error'] = str(e)
        else:
            # Si ce n'est pas une image disque, essayer d'analyser le disque hôte
            try:
                # Analyse du disque système
                fls_cmd = ['fls', '-r', '/host/dev/sda']
                fls_result = self.execute_command(fls_cmd)
                results['host_disk_fls'] = fls_result

                # Analyse de la table de partition
                mmls_cmd = ['mmls', '/host/dev/sda']
                mmls_result = self.execute_command(mmls_cmd)
                results['host_disk_mmls'] = mmls_result
            except Exception as e:
                self.log(f"Erreur lors de l'analyse du disque hôte: {str(e)}")
                results['host_disk_error'] = str(e)

        return results

    def analyze_with_volatility(self):
        """Analyse avec Volatility."""
        results = {}
        
        # Vérification si c'est un dump mémoire
        if any(self.file_path.lower().endswith(ext) for ext in MEMORY_EXTENSIONS):
            try:
                # Détection du profil
                profile_cmd = ['vol', '-f', self.file_path, 'imageinfo']
                profile_result = self.execute_command(profile_cmd)
                results['profile'] = profile_result

                # Analyse des processus
                pslist_cmd = ['vol', '-f', self.file_path, '--profile', 'Win7SP1x64', 'pslist']
                pslist_result = self.execute_command(pslist_cmd)
                results['pslist'] = pslist_result

                # Analyse des connexions réseau
                netscan_cmd = ['vol', '-f', self.file_path, '--profile', 'Win7SP1x64', 'netscan']
                netscan_result = self.execute_command(netscan_cmd)
                results['netscan'] = netscan_result
            except Exception as e:
                self.log(f"Erreur lors de l'analyse Volatility: {str(e)}")
                results['error'] = str(e)
        else:
            # Si ce n'est pas un dump mémoire, essayer d'analyser la mémoire hôte
            try:
                # Analyse de la mémoire système
                mem_cmd = ['vol', '-f', '/host/proc/kcore', 'imageinfo']
                mem_result = self.execute_command(mem_cmd)
                results['host_memory'] = mem_result
            except Exception as e:
                self.log(f"Erreur lors de l'analyse de la mémoire hôte: {str(e)}")
                results['host_memory_error'] = str(e)

        return results

    def send_to_api(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Envoie le rapport à l'API avec gestion des erreurs."""
        if not API_CONFIG['enabled']:
            return {"status": "API disabled"}

        # Préparation des données pour l'API
        api_data = {
            "file_name": self.file_name,
            "analysis_date": datetime.now().isoformat(),
            "analysis_results": report_data
        }

        for attempt in range(API_CONFIG['retries']):
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
                
                response = requests.post(
                    self.api_endpoint,
                    json=api_data,
                    headers=headers,
                    timeout=API_CONFIG['timeout']
                )
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                self.log(f"Tentative {attempt + 1}/{API_CONFIG['retries']} échouée: {str(e)}")
                if attempt == API_CONFIG['retries'] - 1:
                    return {
                        "error": f"Échec de l'envoi à l'API après {API_CONFIG['retries']} tentatives",
                        "details": str(e)
                    }
                continue
        return {"error": "Erreur inconnue lors de l'envoi à l'API"}

    def analyze(self):
        """Analyse le fichier et envoie le rapport à l'API."""
        try:
            # Collecte des données
            report_data = {
                "timestamp": self.timestamp,
                "file_info": {
                    "name": self.file_name,
                    "size": os.path.getsize(self.file_path),
                    "type": magic.from_file(self.file_path, mime=True),
                    "md5": self.calculate_md5(),
                    "sha256": self.calculate_sha256()
                },
                "analysis": {
                    "clamav": self.scan_clamav(),
                    "yara": self.scan_yara(),
                    "exif": self.get_exif_data(),
                    "sleuthkit": self.analyze_with_sleuthkit(),
                    "volatility": self.analyze_with_volatility()
                }
            }

            # Envoi à l'API
            api_response = self.send_to_api(report_data)
            report_data["api_response"] = api_response

            # Sauvegarde locale du rapport
            output_file = os.path.join(self.output_dir, f"report_{self.timestamp}.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, cls=DateTimeEncoder, ensure_ascii=False)

            return report_data

        except Exception as e:
            error_data = {
                "error": str(e),
                "timestamp": self.timestamp,
                "file": self.file_name
            }
            self.log(f"Erreur lors de l'analyse: {str(e)}")
            return error_data

    def calculate_md5(self) -> str:
        """Calcule le hash MD5 du fichier."""
        try:
            with open(self.file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            self.log(f"Erreur lors du calcul du MD5: {str(e)}")
            return ""

    def calculate_sha256(self) -> str:
        """Calcule le hash SHA256 du fichier."""
        try:
            with open(self.file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            self.log(f"Erreur lors du calcul du SHA256: {str(e)}")
            return ""

def main():
    if len(sys.argv) != 2:
        print("Usage: python forensic_analyzer.py <chemin_du_fichier>")
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"Erreur: Le fichier {file_path} n'existe pas.")
        sys.exit(1)

    analyzer = ForensicAnalyzer(file_path)
    results = analyzer.analyze()
    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()           
