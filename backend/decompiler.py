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

    def _kill_process(self, process):
        """Tue proprement un processus (Windows + Unix)."""
        if process is None or process.poll() is not None:
            return
        try:
            if os.name == 'nt':
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
            else:
                try:
                    os.killpg(os.getpgid(process.pid), 15)  # SIGTERM
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(os.getpgid(process.pid), 9)   # SIGKILL
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

    def _collect_java_files(self, output_dir: str, max_files: int) -> tuple:
        """
        Collecte les fichiers .java dans output_dir/sources (ou output_dir direct).
        Retourne (java_files_list, packages_set).
        Fonctionne même si jadx a produit une sortie partielle.
        """
        java_files = []
        packages = set()
        count = 0

        # jadx peut écrire dans sources/ ou directement dans output_dir
        candidates = [
            os.path.join(output_dir, "sources"),
            output_dir,
        ]
        java_dir = None
        for c in candidates:
            if os.path.exists(c) and any(
                f.endswith(".java")
                for _, _, files in os.walk(c)
                for f in files
            ):
                java_dir = c
                break

        if java_dir is None:
            return java_files, packages

        for root, dirs, files in os.walk(java_dir):
            for file in files:
                if not file.endswith(".java"):
                    continue
                if count >= max_files:
                    break
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, java_dir).replace("\\", "/")
                package_name = rel_path.replace(".java", "").replace("/", ".")
                parts = rel_path.split("/")
                if len(parts) > 1:
                    packages.add(parts[0])
                try:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    java_files.append({
                        "path": rel_path,
                        "package": package_name,
                        "name": file,
                        "content": content[:10000],
                        "methods": extract_methods(content),
                        "strings": extract_strings(content),
                    })
                    count += 1
                except Exception:
                    pass

        return java_files, packages

    def decompile_java(self, apk_content: bytes, max_files: int = 50) -> Dict[str, Any]:
        """
        Décompile l'APK en Java source avec jadx.
        
        Stratégie robuste en 3 passes pour gérer TOUS les types d'APK :
          1. Passe normale  : jadx standard (APK propres)
          2. Passe permissive: jadx --no-res --no-imports --show-bad-code (APK obfusqués/protégés)
          3. Passe partielle : récupère les fichiers produits même si jadx a retourné une erreur
        
        Résultat : même sur un APK protégé, on récupère ce que jadx a pu décompiler.
        """
        result = {
            "available": self.jadx_available,
            "error": None,
            "warning": None,
            "java_files": [],
            "packages": [],
            "decompile_mode": "none",
        }

        if not self.jadx_available:
            result["error"] = "jadx n'est pas installé. Installez avec: apt install jadx ou brew install jadx"
            return result

        temp_dir = tempfile.mkdtemp()
        process = None

        try:
            apk_path = os.path.join(temp_dir, "app.apk")
            with open(apk_path, "wb") as f:
                f.write(apk_content)

            jadx_cmd = self._get_cmd("jadx")

            # ── Passe 1 : décompilation standard ──────────────────────────────
            output_dir_1 = os.path.join(temp_dir, "pass1")
            args_1 = [jadx_cmd, apk_path, "-d", output_dir_1,
                      "--threads-count", "4",
                      "-q"]
            try:
                process = subprocess.Popen(
                    args_1,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid if os.name != 'nt' else None,
                )
                try:
                    stdout1, stderr1 = process.communicate(timeout=300)
                except subprocess.TimeoutExpired:
                    self._kill_process(process)
                    process = None
                    stdout1, stderr1 = b"", b"Timeout passe 1"
            except KeyboardInterrupt:
                self._kill_process(process)
                result["error"] = "Décompilation interrompue"
                return result
            except Exception as e:
                stdout1, stderr1 = b"", str(e).encode()
            finally:
                self._kill_process(process)
                process = None

            java_files_1, packages_1 = self._collect_java_files(output_dir_1, max_files)

            if java_files_1:
                # Succès passe 1
                result["java_files"] = java_files_1
                result["packages"] = sorted(packages_1)
                result["decompile_mode"] = "standard"
                return result

            # ── Passe 2 : mode permissif (APK obfusqués / protégés) ───────────
            # --show-bad-code     : inclut les classes que jadx n'a pas pu décompiler proprement
            # --no-res            : ignore les ressources (évite les crashes sur res corrompus)
            # --no-imports        : évite les erreurs d'imports non résolus
            # --deobf             : tente la désobfuscation basique (renommage classes/méthodes)
            # --escape-unicode    : évite les crashs sur caractères spéciaux dans les strings
            output_dir_2 = os.path.join(temp_dir, "pass2")
            args_2 = [jadx_cmd, apk_path, "-d", output_dir_2,
                      "--show-bad-code",
                      "--no-res",
                      "--no-imports",
                      "--deobf",
                      "--escape-unicode",
                      "--threads-count", "4",
                      "-q"]
            try:
                process = subprocess.Popen(
                    args_2,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid if os.name != 'nt' else None,
                )
                try:
                    stdout2, stderr2 = process.communicate(timeout=300)
                except subprocess.TimeoutExpired:
                    self._kill_process(process)
                    process = None
                    stdout2, stderr2 = b"", b"Timeout passe 2"
            except KeyboardInterrupt:
                self._kill_process(process)
                result["error"] = "Décompilation interrompue"
                return result
            except Exception as e:
                stdout2, stderr2 = b"", str(e).encode()
            finally:
                self._kill_process(process)
                process = None

            java_files_2, packages_2 = self._collect_java_files(output_dir_2, max_files)

            if java_files_2:
                result["java_files"] = java_files_2
                result["packages"] = sorted(packages_2)
                result["decompile_mode"] = "permissive"
                result["warning"] = (
                    "APK obfusqué ou protégé — décompilation partielle en mode permissif. "
                    "Certaines classes peuvent être incomplètes ou renommées."
                )
                return result

            # ── Passe 3 : récupération partielle ──────────────────────────────
            # Même si jadx a échoué globalement, il a peut-être produit des fichiers.
            # On cherche dans les deux dossiers de sortie.
            for out_dir in [output_dir_1, output_dir_2]:
                partial_files, partial_packages = self._collect_java_files(out_dir, max_files)
                if partial_files:
                    result["java_files"] = partial_files
                    result["packages"] = sorted(partial_packages)
                    result["decompile_mode"] = "partial"
                    result["warning"] = (
                        "Décompilation partielle — jadx a échoué sur certaines classes "
                        "(APK très protégé, multi-dex complexe ou bytecode non standard). "
                        f"Fichiers récupérés : {len(partial_files)}"
                    )
                    return result

            # ── Échec total ───────────────────────────────────────────────────
            # On construit un message d'erreur utile à partir de stdout+stderr
            all_output = (
                (stdout1 or b"") + (stderr1 or b"") +
                (stdout2 or b"") + (stderr2 or b"")
            ).decode("utf-8", errors="replace").strip()

            if not all_output:
                all_output = (
                    "jadx n'a produit aucun fichier Java et aucun message d'erreur. "
                    "L'APK est probablement protégé par un packer (DexGuard, AppShielding, etc.) "
                    "ou son bytecode est non standard. Essayez apktool pour le Smali."
                )
            else:
                # Tronquer pour ne pas polluer la réponse
                all_output = all_output[:800]

            result["error"] = f"JADX — décompilation impossible après 2 passes : {all_output}"
            result["decompile_mode"] = "failed"
            return result

        except Exception as e:
            result["error"] = f"Erreur décompilation Java: {str(e)}"
            return result
        finally:
            self._kill_process(process)
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