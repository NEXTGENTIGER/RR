#!/usr/bin/env python3
import os
import json
import hashlib
import subprocess
import requests
import magic
import yara
import clamd
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
    'bulk_extractor': {
        'commands': {
            'Windows': ['bulk_extractor.exe'],
            'Linux': ['bulk_extractor'],
            'Darwin': ['bulk_extractor']
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

# Importation conditionnelle de clamd
try:
    import clamd
    CLAMD_AVAILABLE = True
except ImportError:
    CLAMD_AVAILABLE = False
    print("Warning: clamd module not available. ClamAV scanning will be disabled.")

class DateTimeEncoder(JSONEncoder):
    """Encodeur personnalisé pour gérer les objets datetime dans le JSON."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class ForensicAnalyzer:
    def __init__(self, file_path, api_endpoint="http://localhost:5000/api/report"):
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.api_endpoint = api_endpoint
        self.output_dir = "/app/output"
        self.log_dir = "/app/logs"
        self.rules_dir = "/app/rules"
        self.setup_directories()
        self.setup_logging()
        if CLAMD_AVAILABLE:
            try:
                self.clamd_client = clamd.ClamdUnixSocket()
            except Exception as e:
                print(f"Warning: Could not connect to ClamAV daemon: {e}")
                CLAMD_AVAILABLE = False

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
        if not CLAMD_AVAILABLE:
            return {"status": "ClamAV scanning disabled - module not available"}
        
        try:
            result = self.clamd_client.scan(self.file_path)
            return result.get(self.file_path, {})
        except Exception as e:
            self.log(f"Erreur lors de l'analyse ClamAV: {str(e)}")
            return {"error": str(e)}

    def scan_yara(self):
        """Analyse le fichier avec YARA."""
        try:
            rules_path = os.path.join(self.rules_dir, "malware.yar")
            if os.path.exists(rules_path):
                rules = yara.compile(filepath=rules_path)
                matches = rules.match(self.file_path)
                return [match.rule for match in matches]
            else:
                self.log("Aucun fichier de règles YARA trouvé")
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
        
        # Analyse avec fls
        fls_result = self.execute_command(['fls', self.file_path])
        results['fls'] = fls_result
        
        # Analyse avec mmls
        mmls_result = self.execute_command(['mmls', self.file_path])
        results['mmls'] = mmls_result
        
        return results

    def analyze_with_volatility(self):
        """Analyse avec Volatility si c'est un dump mémoire."""
        try:
            mime_type = magic.from_file(self.file_path, mime=True)
            if 'memory' in mime_type.lower() or 'dump' in mime_type.lower():
                results = {}
                
                # Analyse des processus
                pslist = self.execute_command(['volatility', '-f', self.file_path, 'windows.pslist'])
                results['pslist'] = pslist
                
                # Analyse des connexions réseau
                netscan = self.execute_command(['volatility', '-f', self.file_path, 'windows.netscan'])
                results['netscan'] = netscan
                
                return results
            return {"status": "Not a memory dump"}
        except Exception as e:
            self.log(f"Erreur lors de l'analyse Volatility: {str(e)}")
            return {"error": str(e)}

    def analyze(self):
        """Exécute l'analyse complète du fichier."""
        self.log(f"Début de l'analyse du fichier: {self.file_path}")
        
        results = {
            "timestamp": self.timestamp,
            "fichier": self.get_basic_metadata(),
            "clamav": self.scan_clamav(),
            "yara": self.scan_yara(),
            "exif": self.get_exif_data(),
            "sleuthkit": self.analyze_with_sleuthkit(),
            "volatility": self.analyze_with_volatility()
        }

        # Sauvegarde des résultats
        output_file = os.path.join(self.output_dir, f"{self.file_name}_report_{self.timestamp}.json")
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)

        # Envoi des résultats à l'API
        try:
            response = requests.post(
                self.api_endpoint,
                json=results,
                headers={"Content-Type": "application/json"}
            )
            results["api_response"] = {
                "status_code": response.status_code,
                "message": response.text
            }
        except Exception as e:
            results["api_response"] = {
                "error": str(e)
            }

        self.log(f"Analyse terminée. Résultats sauvegardés dans: {output_file}")
        return results

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