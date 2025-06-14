#!/usr/bin/env python3
import os
import json
import hashlib
import subprocess
import magic
import yara
import logging
import platform
import sys
from datetime import datetime
from typing import Dict, Any
from json import JSONEncoder
from pathlib import Path

# Configuration des logs
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = logging.INFO
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "forensic_analyzer.log"

# Extensions connues
MEMORY_EXTENSIONS = {'.dmp', '.mem', '.raw', '.img', '.dump'}
DISK_EXTENSIONS = {'.dd', '.img', '.raw', '.vmdk', '.vhd', '.vhdx'}

# Règles YARA internes
YARA_RULES = """
rule Suspicious_Strings {
    meta:
        description = "Chaînes suspectes"
    strings:
        $a = "cmd.exe"
        $b = "powershell"
        $c = "SUSPICIOUS_PATTERN_1"
    condition:
        any of them
}
"""

class DateTimeEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class ForensicAutoAnalyzer:
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.rules = yara.compile(source=YARA_RULES)
        os.makedirs("logs", exist_ok=True)
        os.makedirs("output", exist_ok=True)

    def execute(self, cmd):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except Exception as e:
            return '', str(e), -1

    def detect_disks(self):
        # Détection de disques montés localement
        disks = []
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.split()
                    if parts[0].startswith("/dev/") and parts[1].startswith("/"):
                        disks.append(parts[0])
        except Exception:
            pass
        return list(set(disks))

    def detect_memory(self):
        # Rechercher un dump RAM courant dans /proc
        kcore = "/proc/kcore"
        return kcore if os.path.exists(kcore) else None

    def analyze_file(self, file_path):
        result = {
            "timestamp": self.timestamp,
            "file": file_path,
            "md5": self.hash_file(file_path, hashlib.md5),
            "sha256": self.hash_file(file_path, hashlib.sha256),
            "mime": magic.from_file(file_path, mime=True),
            "yara": []
        }
        try:
            matches = self.rules.match(file_path)
            for m in matches:
                result["yara"].append(m.rule)
        except Exception as e:
            result["yara_error"] = str(e)
        return result

    def hash_file(self, path, algo):
        h = algo()
        try:
            with open(path, 'rb') as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def run(self):
        disk_devices = self.detect_disks()
        memory_file = self.detect_memory()

        print("Disques détectés:", disk_devices)
        print("Dump mémoire détecté:", memory_file if memory_file else "Non détecté")

        reports = []
        for dev in disk_devices:
            reports.append({"disk_device": dev})

        if memory_file:
            reports.append(self.analyze_file(memory_file))

        report_path = f"output/system_scan_{self.timestamp}.json"
        with open(report_path, 'w') as f:
            json.dump(reports, f, indent=2, cls=DateTimeEncoder)
        print(f"Rapport sauvegardé: {report_path}")

if __name__ == "__main__":
    analyzer = ForensicAutoAnalyzer()
    analyzer.run()
