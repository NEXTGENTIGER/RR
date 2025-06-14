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

# Configuration
API_CONFIG = {
    'endpoint': 'http://127.0.0.1:5000/api/v1/report/upload_json/',
    'timeout': 30,
    'max_retries': 3
}

# Extensions de fichiers à analyser
ANALYZED_EXTENSIONS = {
    # Exécutables
    '.exe', '.dll', '.sys', '.drv', '.bin',
    # Scripts
    '.bat', '.cmd', '.ps1', '.vbs', '.js', '.py',
    # Documents
    '.doc', '.docx', '.xls', '.xlsx', '.pdf',
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp',
    # Archives
    '.zip', '.rar', '.7z', '.tar', '.gz',
    # Autres
    '.txt', '.log', '.ini', '.conf'
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

rule Suspicious_IP_Address {
    meta:
        description = "Détecte les adresses IP suspectes"
        severity = "MEDIUM"
    strings:
        $ip = /[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/
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
    def __init__(self, target_path, api_endpoint=None):
        self.target_path = target_path
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
        self.log_file = os.path.join(self.log_dir, f"forensic_analyzer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        with open(self.log_file, 'w') as f:
            f.write(f"=== Début de l'analyse: {datetime.now().strftime('%Y%m%d_%H%M%S')} ===\n")

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
            file_stats = os.stat(self.target_path)
            return {
                "nom": os.path.basename(self.target_path),
                "taille": file_stats.st_size,
                "date_creation": datetime.fromtimestamp(file_stats.st_ctime).isoformat(),
                "date_modification": datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                "type_mime": magic.from_file(self.target_path, mime=True)
            }
        except Exception as e:
            self.log(f"Erreur lors de la récupération des métadonnées: {str(e)}")
            return {}

    def scan_clamav(self, file_path):
        """Analyse le fichier avec ClamAV."""
        if self.clamd_client is None:
            return {"status": "ClamAV scanning disabled - daemon not available"}
        
        try:
            result = self.clamd_client.scan(file_path)
            if not result:
                return {"status": "No threats found", "details": "File is clean"}
            return result.get(file_path, {})
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

    def scan_yara(self, file_path):
        """Analyse le fichier avec YARA."""
        try:
            if self.yara_rules:
                matches = self.yara_rules.match(file_path)
                if not matches:
                    return [{"rule": "No_YARA_Matches", "meta": {"description": "No suspicious patterns found"}}]
                return [{
                    'rule': match.rule,
                    'meta': match.meta,
                    'strings': [str(s) for s in match.strings]
                } for match in matches]
            return [{"rule": "YARA_Not_Available", "meta": {"description": "YARA rules not loaded"}}]
        except Exception as e:
            self.log(f"Erreur lors de l'analyse YARA: {str(e)}")
            return [{"rule": "YARA_Error", "meta": {"description": str(e)}}]

    def get_exif_data(self, file_path):
        """Récupère les métadonnées EXIF avec exiftool."""
        try:
            result = self.execute_command(['exiftool', '-j', file_path])
            if not result.get('success'):
                return {
                    "success": False,
                    "output": "No EXIF data found",
                    "error": result.get('error', 'Unknown error')
                }
            return result
        except Exception as e:
            return {
                "success": False,
                "output": None,
                "error": str(e)
            }

    def analyze_with_sleuthkit(self, file_path):
        """Analyse avec SleuthKit."""
        results = {}
        
        # Vérification si c'est une image disque
        if any(file_path.lower().endswith(ext) for ext in DISK_EXTENSIONS):
            try:
                # Analyse avec fls
                fls_cmd = ['fls', '-r', file_path]
                fls_result = self.execute_command(fls_cmd)
                results['fls'] = fls_result

                # Analyse avec mmls
                mmls_cmd = ['mmls', file_path]
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

        if not results:
            results['status'] = "No disk analysis possible"
        return results

    def analyze_with_volatility(self, file_path):
        """Analyse avec Volatility."""
        results = {}
        
        # Vérification si c'est un dump mémoire
        if any(file_path.lower().endswith(ext) for ext in MEMORY_EXTENSIONS):
            try:
                # Détection du profil
                profile_cmd = ['vol', '-f', file_path, 'imageinfo']
                profile_result = self.execute_command(profile_cmd)
                results['profile'] = profile_result

                # Analyse des processus
                pslist_cmd = ['vol', '-f', file_path, '--profile', 'Win7SP1x64', 'pslist']
                pslist_result = self.execute_command(pslist_cmd)
                results['pslist'] = pslist_result

                # Analyse des connexions réseau
                netscan_cmd = ['vol', '-f', file_path, '--profile', 'Win7SP1x64', 'netscan']
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

        if not results:
            results['status'] = "No memory analysis possible"
        return results

    def analyze_target(self):
        """Analyse le chemin cible (fichier ou répertoire)."""
        results = {
            "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "target_info": self.get_target_info(),
            "analysis": {
                "files": [],
                "system": self.analyze_system(),
                "summary": {}
            }
        }

        if os.path.isfile(self.target_path):
            # Analyse d'un fichier unique
            file_analysis = self.analyze_file(self.target_path)
            results["analysis"]["files"].append(file_analysis)
        else:
            # Analyse récursive d'un répertoire
            for root, _, files in os.walk(self.target_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if any(file.lower().endswith(ext) for ext in ANALYZED_EXTENSIONS):
                        file_analysis = self.analyze_file(file_path)
                        results["analysis"]["files"].append(file_analysis)

        # Génération du résumé
        results["analysis"]["summary"] = self.generate_summary(results["analysis"]["files"])
        
        # Sauvegarde et envoi des résultats
        self.save_results(results)
        self.send_to_api(results)
        
        return results

    def get_target_info(self):
        """Récupère les informations sur la cible."""
        info = {
            "path": self.target_path,
            "type": "directory" if os.path.isdir(self.target_path) else "file",
            "size": self.get_size(self.target_path),
            "permissions": self.get_permissions(self.target_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(self.target_path)).isoformat()
        }
        return info

    def analyze_system(self):
        """Analyse le système hôte."""
        return {
            "os_info": self.get_os_info(),
            "disk_info": self.analyze_with_sleuthkit("/host"),
            "memory_info": self.analyze_with_volatility("/host"),
            "network_info": self.get_network_info()
        }

    def get_os_info(self):
        """Récupère les informations sur le système d'exploitation."""
        try:
            uname = os.uname()
            return {
                "system": uname.sysname,
                "node": uname.nodename,
                "release": uname.release,
                "version": uname.version,
                "machine": uname.machine
            }
        except:
            return {"error": "Impossible de récupérer les informations système"}

    def get_network_info(self):
        """Récupère les informations réseau."""
        try:
            result = self.execute_command(['netstat', '-tuln'])
            return result
        except:
            return {"error": "Impossible de récupérer les informations réseau"}

    def analyze_file(self, file_path):
        """Analyse un fichier individuel."""
        return {
            "file_info": self.get_file_info(file_path),
            "clamav": self.scan_clamav(file_path),
            "yara": self.scan_yara(file_path),
            "exif": self.get_exif_data(file_path),
            "sleuthkit": self.analyze_with_sleuthkit(file_path),
            "volatility": self.analyze_with_volatility(file_path)
        }

    def get_file_info(self, file_path):
        """Récupère les informations de base sur un fichier."""
        try:
            file_stat = os.stat(file_path)
            return {
                "name": os.path.basename(file_path),
                "size": file_stat.st_size,
                "type": magic.from_file(file_path, mime=True),
                "md5": self.calculate_hash(file_path, 'md5'),
                "sha256": self.calculate_hash(file_path, 'sha256'),
                "permissions": oct(file_stat.st_mode)[-3:],
                "last_modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat()
            }
        except Exception as e:
            return {"error": str(e)}

    def calculate_hash(self, file_path, algorithm='sha256'):
        """Calcule le hash d'un fichier."""
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            return f"Error calculating {algorithm}: {str(e)}"

    def generate_summary(self, file_analyses):
        """Génère un résumé de l'analyse."""
        summary = {
            "total_files": len(file_analyses),
            "suspicious_files": 0,
            "infected_files": 0,
            "file_types": {},
            "threats": []
        }

        for analysis in file_analyses:
            # Comptage des types de fichiers
            file_type = analysis["file_info"].get("type", "unknown")
            summary["file_types"][file_type] = summary["file_types"].get(file_type, 0) + 1

            # Détection des menaces
            if analysis["clamav"].get("status") == "FOUND":
                summary["infected_files"] += 1
                summary["threats"].append({
                    "file": analysis["file_info"]["name"],
                    "type": "virus",
                    "details": analysis["clamav"]
                })

            if analysis["yara"]:
                summary["suspicious_files"] += 1
                for match in analysis["yara"]:
                    summary["threats"].append({
                        "file": analysis["file_info"]["name"],
                        "type": "suspicious",
                        "details": match
                    })

        return summary

    def save_results(self, results):
        """Sauvegarde les résultats de l'analyse."""
        try:
            # Création du nom de fichier avec timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.output_dir, f"report_{timestamp}.json")
            
            # Sauvegarde en JSON avec indentation
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.log(f"Résultats sauvegardés dans {output_file}")
            return True
        except Exception as e:
            self.log(f"Erreur lors de la sauvegarde des résultats: {str(e)}")
            return False

    def send_to_api(self, results):
        """Envoie les résultats à l'API."""
        try:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Formatage des données pour l'API
            api_data = {
                "file_name": os.path.basename(self.target_path),
                "analysis_date": datetime.now().isoformat(),
                "analysis_results": results
            }

            # Tentatives d'envoi
            for attempt in range(API_CONFIG['max_retries']):
                try:
                    response = requests.post(
                        self.api_endpoint,
                        json=api_data,
                        headers=headers,
                        timeout=API_CONFIG['timeout']
                    )
                    response.raise_for_status()
                    return response.json()
                except requests.exceptions.RequestException as e:
                    if attempt == API_CONFIG['max_retries'] - 1:
                        raise e
                    continue

        except Exception as e:
            self.log(f"Erreur lors de l'envoi à l'API: {str(e)}")
            return {
                "error": f"Échec de l'envoi à l'API après {API_CONFIG['max_retries']} tentatives",
                "details": str(e)
            }

def main():
    if len(sys.argv) != 2:
        print("Usage: python forensic_analyzer.py <target_path>")
        sys.exit(1)

    target_path = sys.argv[1]
    analyzer = ForensicAnalyzer(target_path)
    results = analyzer.analyze_target()
    
    # Affichage des résultats
    print(json.dumps(results, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()           
