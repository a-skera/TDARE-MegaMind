"""
Reverse Engineering Engine
Analyzes executables using Ghidra and extracts structured information.
"""

import hashlib
import json
import logging
import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Kali/Debian ghidra package layout - override with env GHIDRA_BINARY (must point to analyzeHeadless).
_DEFAULT_ANALYZE_HEADLESS = Path("/usr/share/ghidra/support/analyzeHeadless")


class ReverseEngine:
    """Reverse engineering analysis engine using Ghidra."""

    def __init__(
        self,
        ghidra_binary: Optional[str] = None,
        project_path: Optional[str] = None,
        project_name: str = "AutoProject",
        scripts_path: Optional[str] = None,
        reports_dir: Optional[str] = None,
        base_dir: Optional[str] = None,
    ):
        home = Path.home()
        base = Path(base_dir) if base_dir else home / "TDARE"

        resolved = (ghidra_binary or os.getenv("GHIDRA_BINARY") or "").strip()
        if resolved:
            self.ghidra_binary = Path(resolved).expanduser()
        else:
            self.ghidra_binary = Path(_DEFAULT_ANALYZE_HEADLESS)

        try:
            self.ghidra_binary = self.ghidra_binary.resolve()
        except OSError:
            pass

        self.project_path = Path(project_path) if project_path else base / "GhidraProject"
        self.project_name = project_name
        self.scripts_path = Path(scripts_path) if scripts_path else base / "GhidraScripts"
        self.reports_dir = Path(reports_dir) if reports_dir else base / "GhidraReports"

        self.project_path = self.project_path.expanduser()
        self.scripts_path = self.scripts_path.expanduser()
        self.reports_dir = self.reports_dir.expanduser()
        try:
            self.project_path = self.project_path.resolve()
            self.scripts_path = self.scripts_path.resolve()
            self.reports_dir = self.reports_dir.resolve()
        except OSError:
            pass

        self.project_path.mkdir(parents=True, exist_ok=True)
        self.scripts_path.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            "ReverseEngine init: ghidra=%s project=%s scripts=%s reports=%s",
            self.ghidra_binary,
            self.project_path,
            self.scripts_path,
            self.reports_dir,
        )

    def _create_json_export_script(self, output_json_abs: Path) -> Path:
        """Create Ghidra postScript that writes JSON to a fixed absolute path."""
        script_path = self.scripts_path / "export_analysis_json.py"
        out_literal = json.dumps(str(output_json_abs))

        script_content = '''# -*- coding: utf-8 -*-
# @category Reporting
# TDARE: export analysis to JSON. Jython 2 compatible. Errors in analysis_data["errors"].
# @runtime Jython

from __future__ import print_function

import json
import os
import traceback

output_file = {out_literal}

def _ensure_parent_dir(path):
    """Python 2 / Jython: no exist_ok on makedirs."""
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent)

def _atomic_write_json(obj, path):
    """Write JSON atomically: temp file, flush+fsync, rename."""
    _ensure_parent_dir(path)
    tmp_path = path + ".tmp"
    f = open(tmp_path, "w")
    try:
        json.dump(obj, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    finally:
        f.close()
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass
    os.rename(tmp_path, path)

def _write_json_best_effort(obj, path):
    """Always try to leave a JSON file; return True if write OK."""
    try:
        _atomic_write_json(obj, path)
        return True
    except Exception, ex:
        try:
            _ensure_parent_dir(path)
            f = open(path, "w")
            try:
                json.dump(obj, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            finally:
                f.close()
            return True
        except Exception, ex2:
            print("[POSTSCRIPT ERROR] write failed: " + str(ex) + " | fallback: " + str(ex2))
            return False

def _iter_functions_safe(func_mgr):
    if func_mgr is None:
        return
    try:
        funcs = func_mgr.getFunctions(True)
        while funcs.hasNext():
            yield funcs.next()
    except Exception, e:
        raise RuntimeError("function iterator: " + str(e))

def _iter_defined_data_safe(listing):
    if listing is None:
        return
    try:
        dd = listing.getDefinedData(True)
        while dd.hasNext():
            yield dd.next()
    except Exception:
        try:
            for s in listing.getDefinedData(True):
                yield s
        except Exception, e2:
            raise RuntimeError("defined data iterator: " + str(e2))

print("[POSTSCRIPT START]")

analysis_data = {{
    "sample_name": "",
    "sample_path": "",
    "architecture": "",
    "functions": [],
    "strings": [],
    "imports": [],
    "sections": [],
    "errors": []
}}

try:
    if currentProgram is None:
        analysis_data["errors"].append("currentProgram is None - cannot export (no binary loaded for postScript)")
    else:
        try:
            analysis_data["sample_name"] = currentProgram.getName() or ""
        except Exception, e:
            analysis_data["errors"].append("sample_name: " + str(e))
        try:
            analysis_data["sample_path"] = str(currentProgram.getExecutablePath() or "")
        except Exception, e:
            analysis_data["errors"].append("sample_path: " + str(e))
        try:
            analysis_data["architecture"] = str(currentProgram.getLanguageID() or "")
        except Exception, e:
            analysis_data["errors"].append("architecture: " + str(e))

        try:
            for func in _iter_functions_safe(currentProgram.getFunctionManager()):
                try:
                    analysis_data["functions"].append({{
                        "name": func.getName(),
                        "address": str(func.getEntryPoint()),
                        "signature": str(func.getSignature())
                    }})
                except Exception, fe:
                    analysis_data["errors"].append("function row: " + str(fe))
        except Exception, e:
            analysis_data["errors"].append("functions: " + str(e))

        try:
            listing = currentProgram.getListing()
            for s in _iter_defined_data_safe(listing):
                try:
                    dt = s.getDataType()
                    dname = str(dt.getName()).lower() if dt else ""
                    if not dname:
                        continue
                    if "string" in dname or "unicode" in dname:
                        val = s.getValue()
                        value = str(val) if val is not None else ""
                        if value and len(value) > 1:
                            analysis_data["strings"].append({{
                                "value": value,
                                "address": str(s.getMinAddress())
                            }})
                except Exception, se:
                    analysis_data["errors"].append("string row: " + str(se))
        except Exception, e:
            analysis_data["errors"].append("strings: " + str(e))

        try:
            symbol_table = currentProgram.getSymbolTable()
            if symbol_table is not None:
                ext = symbol_table.getExternalSymbols()
                seen = set()
                while ext.hasNext():
                    sym = ext.next()
                    try:
                        name = sym.getName()
                        addr = str(sym.getAddress()) if sym.getAddress() else "EXTERNAL"
                        key = (name, addr)
                        if key not in seen:
                            seen.add(key)
                            analysis_data["imports"].append({{
                                "name": name,
                                "address": addr
                            }})
                    except Exception, ie:
                        analysis_data["errors"].append("import row: " + str(ie))
        except Exception, e:
            analysis_data["errors"].append("imports: " + str(e))

        try:
            memory = currentProgram.getMemory()
            if memory is not None:
                blocks = memory.getBlocks()
                if blocks is not None:
                    for block in blocks:
                        try:
                            analysis_data["sections"].append({{
                                "name": block.getName(),
                                "start": str(block.getStart()),
                                "end": str(block.getEnd()),
                                "size": str(block.getSize()),
                                "permissions": {{
                                    "read": block.isRead(),
                                    "write": block.isWrite(),
                                    "execute": block.isExecute()
                                }}
                            }})
                        except Exception, be:
                            analysis_data["errors"].append("section row: " + str(be))
        except Exception, e:
            analysis_data["errors"].append("sections: " + str(e))

        nf = len(analysis_data["functions"])
        ns = len(analysis_data["strings"])
        ni = len(analysis_data["imports"])
        if nf == 0:
            analysis_data["errors"].append(
                "Diagnostic: 0 functions - possible causes: stripped binary, wrong language loader, or analysis not finished; check Ghidra log."
            )
        if ns == 0:
            analysis_data["errors"].append(
                "Diagnostic: 0 string data items - defined string data may be absent or not typed as string/unicode in listing."
            )
        if ni == 0:
            analysis_data["errors"].append(
                "Diagnostic: 0 external symbols - may be normal for static/stripped ELFs."
            )

except Exception, e:
    analysis_data["errors"].append("fatal: " + traceback.format_exc())

ok = _write_json_best_effort(analysis_data, output_file)
if ok:
    print("[POSTSCRIPT DONE]", output_file)
else:
    print("[POSTSCRIPT ERROR] could not write JSON to " + str(output_file))
'''.format(
            out_literal=out_literal,
        )

        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_content)

        return script_path

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze an executable file using Ghidra."""
        file_path = Path(file_path)

        result: Dict[str, Any] = {
            "sample_name": file_path.name,
            "sample_path": str(file_path),
            "file_hash": "unknown",
            "file_size": 0,
            "file_modified": "unknown",
            "architecture": "Unknown",
            "functions": [],
            "strings": [],
            "imports": [],
            "sections": [],
            "errors": [],
            "warnings": [],
            "debug_logs": [],
            "report_json_path": "",
            "ghidra_command": "",
            "ghidra_project_name": "",
            "analysis_success": False,
        }

        if not file_path.exists():
            result["errors"].append(f"File not found: {file_path}")
            return result

        if not file_path.is_file():
            result["errors"].append(f"Path is not a file: {file_path}")
            return result

        try:
            result["file_hash"] = self._calculate_hash(file_path)
            result["file_size"] = file_path.stat().st_size
            result["file_modified"] = time.ctime(file_path.stat().st_mtime)
        except Exception as e:
            result["warnings"].append(f"Could not read file metadata: {e}")

        if result["file_size"] == 0:
            result["errors"].append(f"Selected file is empty: {file_path}")
            return result

        if not self.ghidra_binary.exists():
            result["errors"].append(
                f"Ghidra analyzeHeadless not found at: {self.ghidra_binary}. "
                "Set GHIDRA_BINARY to the full path of analyzeHeadless (e.g. "
                "/usr/share/ghidra/support/analyzeHeadless)."
            )
            return result
        if not os.access(self.ghidra_binary, os.X_OK):
            result["warnings"].append(
                f"Ghidra binary is not marked executable: {self.ghidra_binary}"
            )

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_file = (self.reports_dir / f"analysis_{timestamp}.json").resolve()
        result["report_json_path"] = str(output_file)

        project_run_name = f"{self.project_name}_{timestamp}"
        result["ghidra_project_name"] = project_run_name

        self._create_json_export_script(output_file)

        file_path = file_path.resolve()
        result["sample_path"] = str(file_path)

        ghidra_bin = str(self.ghidra_binary.resolve())
        proj_dir = str(self.project_path.resolve())
        scripts_dir = str(self.scripts_path.resolve())
        import_path = str(file_path)

        cmd = [
            ghidra_bin,
            proj_dir,
            project_run_name,
            "-import",
            import_path,
            "-scriptPath",
            scripts_dir,
            "-postScript",
            "export_analysis_json.py",
            "-overwrite",
        ]
        result["ghidra_command"] = shlex.join(cmd)
        logger.info("Expected JSON report (success = non-empty parseable file only): %s", output_file)
        logger.info("Full Ghidra command: %s", result["ghidra_command"])
        logger.info(
            "Absolute paths: analyzeHeadless=%s project=%s scriptPath=%s import=%s",
            ghidra_bin,
            proj_dir,
            scripts_dir,
            import_path,
        )
        logger.info(
            "Auto-analysis runs after -import (Ghidra analyzeHeadless has no -analyze flag; "
            "do not pass -noanalysis). -deleteProject is not used."
        )

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                cwd=proj_dir,
            )

            clean_stderr = (process.stderr or "").strip()
            clean_stdout = (process.stdout or "").strip()

            if clean_stderr:
                result["debug_logs"].append(f"STDERR:\n{clean_stderr[:8000]}")
            if clean_stdout:
                result["debug_logs"].append(f"STDOUT:\n{clean_stdout[:8000]}")

            suspicious_words = ["error", "exception", "failed", "traceback"]

            if clean_stderr and any(word in clean_stderr.lower() for word in suspicious_words):
                result["warnings"].append(f"Ghidra stderr: {clean_stderr[:1500]}")

            if clean_stdout and any(word in clean_stdout.lower() for word in suspicious_words):
                result["warnings"].append(f"Ghidra stdout: {clean_stdout[:1500]}")

            read_path = output_file
            result["report_json_path"] = str(read_path)

            if process.returncode != 0:
                result["warnings"].append(
                    f"Ghidra analyzeHeadless exited with code {process.returncode} "
                    "(success is determined only by JSON file presence and parseability)"
                )

            for attempt in range(80):
                if read_path.is_file() and read_path.stat().st_size > 0:
                    break
                time.sleep(0.15)

            if not read_path.is_file() or read_path.stat().st_size == 0:
                result["errors"].append(
                    f"Analysis failed: JSON report missing or zero-length at {read_path}. "
                    "Success requires a non-empty file with valid JSON (stdout is not used)."
                )
            else:
                try:
                    with open(read_path, "r", encoding="utf-8") as f:
                        raw = f.read()
                    if not raw.strip():
                        result["errors"].append(
                            f"JSON report file is empty after read: {read_path}"
                        )
                    else:
                        ghidra_data = json.loads(raw)
                        if isinstance(ghidra_data, dict):
                            result["analysis_success"] = True
                            result["architecture"] = ghidra_data.get("architecture", "Unknown")
                            result["functions"] = ghidra_data.get("functions") or []
                            result["strings"] = ghidra_data.get("strings") or []
                            result["imports"] = ghidra_data.get("imports") or []
                            result["sections"] = ghidra_data.get("sections") or []

                            script_errors = ghidra_data.get("errors", [])
                            if script_errors:
                                result["errors"].extend(script_errors)
                            logger.info(
                                "JSON report loaded: %s (%d bytes, functions=%d)",
                                read_path,
                                read_path.stat().st_size,
                                len(result["functions"]),
                            )
                        else:
                            result["errors"].append("JSON root must be an object")
                            result["analysis_success"] = False

                except json.JSONDecodeError as e:
                    result["analysis_success"] = False
                    result["errors"].append(f"Failed to parse JSON report: {e}")
                except Exception as e:
                    result["analysis_success"] = False
                    result["errors"].append(f"Failed to read analysis report: {e}")

        except subprocess.TimeoutExpired:
            result["errors"].append("Ghidra analysis timed out (exceeded 10 minutes)")
        except PermissionError as e:
            result["errors"].append(f"Permission error during analysis: {e}")
        except FileNotFoundError:
            result["errors"].append(f"Ghidra binary not found at: {self.ghidra_binary}")
        except Exception as e:
            result["errors"].append(f"Error during analysis: {str(e)}")

        return result

    def run(self, file_path: str) -> Dict[str, Any]:
        """
        Run Ghidra analysis on a file. Success is indicated by analysis_success and a
        non-empty, parseable JSON report (stdout is not used for validation).
        """
        return self.analyze_file(file_path)

    def _calculate_hash(self, file_path: Path) -> str:
        """Calculate MD5 hash of file."""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return "unknown"

    def analyze_from_json(self, json_file: str) -> List[Dict[str, Any]]:
        """Analyze files from a JSON log file."""
        results: List[Dict[str, Any]] = []

        try:
            with open(json_file, "r", encoding="utf-8") as f:
                logs = json.load(f)

            if not isinstance(logs, list):
                return [{"error": "JSON input must contain a list of log entries"}]

            for entry in logs:
                file_path = entry.get("file_path")

                if file_path and Path(file_path).exists():
                    analysis = self.analyze_file(file_path)
                    analysis["log_metadata"] = {
                        "event_id": entry.get("event_id"),
                        "timestamp": entry.get("timestamp"),
                        "severity": entry.get("severity"),
                        "description": entry.get("description"),
                    }
                    results.append(analysis)
                else:
                    results.append({
                        "error": f"File not found: {file_path}",
                        "log_metadata": entry,
                    })

        except json.JSONDecodeError as e:
            results.append({
                "error": f"Invalid JSON file: {e}"
            })
        except Exception as e:
            results.append({
                "error": f"Failed to process JSON file: {str(e)}"
            })

        return results