import os
import subprocess
import tempfile
import shutil
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
import zipfile
import io


class APKDecompiler:
    """
    Décompile les APK using apktool (Smali) or jadx (Java source).
    """

    def __init__(self):
        self.apktool_available = self._check_tool("apktool")
        self.jadx_available = self._check_tool("jadx")
        self.strings_pattern = re.compile(r'(https?://[^\s"\'<>)\]},]+|[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z]{2,}){1,3})')

    def _check_tool(self, tool: str) -> bool:
        """Vérifie si l'outil est installé (Windows + Linux/macOS)."""
        # Sur Windows, jadx s'installe comme jadx.bat ou jadx.cmd
        candidates = [tool + ".bat", tool + ".cmd", tool + ".exe", tool] if os.name == 'nt' else [tool]

        for cmd in candidates:
            try:
                result = subprocess.run(
                    [cmd, "--version"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    setattr(self, f"_{tool}_cmd", cmd)
                    return True
            except (FileNotFoundError, PermissionError, OSError):
                continue
            except Exception:
                continue

        # Dernière tentative via where (Windows) ou which (Unix)
        try:
            finder = "where" if os.name == 'nt' else "which"
            found = subprocess.run([finder, tool], capture_output=True, text=True, timeout=5)
            if found.returncode == 0:
                path = found.stdout.strip().splitlines()[0]
                test = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
                if test.returncode == 0:
                    setattr(self, f"_{tool}_cmd", path)
                    return True
        except Exception:
            pass

        return False

    def _get_cmd(self, tool: str) -> str:
        """Retourne le nom de commande exact détecté pour cet outil."""
        return getattr(self, f"_{tool}_cmd", tool)

    def decompile_smali(self, apk_content: bytes, max_files: int = 100) -> Dict[str, Any]:
        """
        Décompile l'APK en Smali (assembleur Android) avec apktool.
        """
        result = {
            "available": self.apktool_available,
            "error": None,
            "smali_files": [],
            "manifest_xml": "",
            "resources_xml": []
        }

        if not self.apktool_available:
            result["error"] = "apktool n'est pas installé. Installez avec: apktool"
            return result

        temp_dir = tempfile.mkdtemp()
        try:
            apk_path = os.path.join(temp_dir, "app.apk")
            output_dir = os.path.join(temp_dir, "decompiled")

            with open(apk_path, "wb") as f:
                f.write(apk_content)

            subprocess.run(
                [self._get_cmd("apktool"), "d", apk_path, "-o", output_dir, "-q"],
                capture_output=True,
                timeout=30
            )

            smali_dir = os.path.join(output_dir, "smali")
            if os.path.exists(smali_dir):
                count = 0
                for root, dirs, files in os.walk(smali_dir):
                    for file in files:
                        if file.endswith(".smali") and count < max_files:
                            filepath = os.path.join(root, file)
                            rel_path = os.path.relpath(filepath, output_dir)
                            try:
                                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                                    content = f.read()
                                result["smali_files"].append({
                                    "path": rel_path.replace("\\", "/"),
                                    "name": file,
                                    "content": content[:2000]
                                })
                                count += 1
                            except:
                                pass

            manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
                        result["manifest_xml"] = f.read()[:10000]
                except:
                    pass

            res_dir = os.path.join(output_dir, "res", "xml")
            if os.path.exists(res_dir):
                for file in os.listdir(res_dir):
                    if file.endswith(".xml"):
                        try:
                            with open(os.path.join(res_dir, file), "r", encoding="utf-8", errors="replace") as f:
                                result["resources_xml"].append({
                                    "name": file,
                                    "content": f.read()[:5000]
                                })
                        except:
                            pass

            return result

        except Exception as e:
            result["error"] = f"Erreur décompilation Smali: {str(e)}"
            return result
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def decompile_java(self, apk_content: bytes, max_files: int = 50) -> Dict[str, Any]:
        """
        Décompile l'APK en Java source avec jadx.
        """
        result = {
            "available": self.jadx_available,
            "error": None,
            "java_files": [],
            "packages": []
        }

        if not self.jadx_available:
            result["error"] = "jadx n'est pas installé. Installez avec: apt install jadx ou brew install jadx"
            return result

        temp_dir = tempfile.mkdtemp()
        process = None
        try:
            apk_path = os.path.join(temp_dir, "app.apk")
            output_dir = os.path.join(temp_dir, "java_src")

            with open(apk_path, "wb") as f:
                f.write(apk_content)

            # Lancer le processus JADX avec gestion d'interruption
            try:
                process = subprocess.Popen(
                    [self._get_cmd("jadx"), apk_path, "-d", output_dir, "-q"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid if os.name != 'nt' else None  # Gérer les signaux sur Unix
                )

                # Attendre la fin du processus avec timeout
                try:
                    stdout, stderr = process.communicate(timeout=120)
                except subprocess.TimeoutExpired:
                    # Timeout atteint, tuer le processus
                    if os.name == 'nt':  # Windows
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                    else:  # Unix
                        os.killpg(os.getpgid(process.pid), subprocess.signal.SIGTERM)
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(os.getpgid(process.pid), subprocess.signal.SIGKILL)
                    result["error"] = "Timeout lors de la décompilation avec JADX"
                    return result

                # Vérifier le code de retour
                if process.returncode != 0:
                    error_msg = stderr.decode('utf-8', errors='replace') if stderr else "Erreur inconnue"
                    result["error"] = f"JADX a échoué: {error_msg}"
                    return result

            except KeyboardInterrupt:
                # Interruption détectée (rechargement du serveur), tuer proprement le processus
                if process and process.poll() is None:
                    try:
                        if os.name == 'nt':  # Windows
                            process.terminate()
                            process.wait(timeout=2)
                        else:  # Unix
                            os.killpg(os.getpgid(process.pid), subprocess.signal.SIGTERM)
                            process.wait(timeout=2)
                    except:
                        try:
                            if os.name == 'nt':
                                process.kill()
                            else:
                                os.killpg(os.getpgid(process.pid), subprocess.signal.SIGKILL)
                        except:
                            pass
                result["error"] = "Décompilation interrompue (rechargement du serveur)"
                return result
            except Exception as e:
                result["error"] = f"Erreur lors du lancement de JADX: {str(e)}"
                return result

            java_dir = os.path.join(output_dir, "sources")
            if os.path.exists(java_dir):
                count = 0
                packages = set()
                for root, dirs, files in os.walk(java_dir):
                    for file in files:
                        if file.endswith(".java") and count < max_files:
                            filepath = os.path.join(root, file)

                            # FIX WINDOWS : utiliser os.path et Path pour
                            # normaliser les séparateurs \ et /
                            rel_path = os.path.relpath(filepath, java_dir)
                            rel_path_normalized = rel_path.replace("\\", "/")

                            # Extraire le package depuis le chemin normalisé
                            package_name = rel_path_normalized.replace(".java", "").replace("/", ".")

                            # Extraire le package racine (premier segment)
                            parts = rel_path_normalized.split("/")
                            if len(parts) > 1:
                                packages.add(parts[0])

                            try:
                                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                                    content = f.read()
                                result["java_files"].append({
                                    "path": rel_path_normalized,
                                    "package": package_name,
                                    "name": file,
                                    "content": content[:3000],
                                    "methods": extract_methods(content),
                                    "strings": extract_strings(content)
                                })
                                count += 1
                            except:
                                pass

                result["packages"] = sorted(list(packages))

            return result

        except Exception as e:
            result["error"] = f"Erreur décompilation Java: {str(e)}"
            return result
        finally:
            # Nettoyer le processus si encore en cours
            if process and process.poll() is None:
                try:
                    if os.name == 'nt':
                        process.terminate()
                        process.wait(timeout=1)
                    else:
                        os.killpg(os.getpgid(process.pid), subprocess.signal.SIGTERM)
                        process.wait(timeout=1)
                except:
                    try:
                        if os.name == 'nt':
                            process.kill()
                        else:
                            os.killpg(os.getpgid(process.pid), subprocess.signal.SIGKILL)
                    except:
                        pass
            # Nettoyer le répertoire temporaire
            shutil.rmtree(temp_dir, ignore_errors=True)

    def extract_secrets_from_code(self, java_files: List[Dict]) -> List[Dict]:
        """
        Détecte les secrets/endpoints/API keys dans le code source.
        """
        secrets = []

        patterns = {
            "api_url": r'((?:https?://|"http)[^"\s<>]{10,})',
            "api_key": r'(["\']?(?:api[_-]?)?(?:key|token|secret|password)["\']?\s*[=:]\s*["\']?[a-zA-Z0-9\-_\.]{20,})',
            "private_ip": r'((?:192\.168|10\.|172\.(?:1[6-9]|2\d|3[01]))\.[\d\.]+)',
            "firebase": r'(https://[a-z0-9\-]+\.firebaseio\.com)',
            "aws": r'(AKIA[0-9A-Z]{16})',
            "oauth": r'([a-zA-Z0-9]{40}\.[a-zA-Z0-9]{40})',
        }

        for file_info in java_files:
            content = file_info["content"]
            for secret_type, pattern in patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    secrets.append({
                        "type": secret_type,
                        "value": match.group(0),
                        "file": file_info["name"],
                        "package": file_info.get("package", "unknown")
                    })

        return secrets[:50]


def extract_methods(java_content: str) -> List[str]:
    """Extrait les noms des méthodes publiques d'une classe Java."""
    methods = []
    pattern = r'public\s+(?:static\s+)?(?:[\w<>]+\s+)?(\w+)\s*\('
    matches = re.finditer(pattern, java_content)
    for match in matches:
        methods.append(match.group(1))
    return list(set(methods))[:20]


def extract_strings(java_content: str) -> List[str]:
    """Extrait les chaînes de caractères (URLs, domaines) du code Java."""
    strings = []
    pattern = r'["\']([^\'"]{10,})["\']'
    matches = re.finditer(pattern, java_content)
    for match in matches:
        value = match.group(1)
        if any(keyword in value.lower() for keyword in ["http", "api", "url", "host", "server", "endpoint"]):
            strings.append(value)
    return list(set(strings))[:20]