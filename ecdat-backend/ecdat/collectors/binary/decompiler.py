"""Decompiler adapter for ECDAT binary scanning.

Provides thin, bounded subprocess wrappers around:
  - JADX  (https://github.com/skylot/jadx) — APK / DEX / JAR -> Java source
  - Ghidra headless (https://ghidra-sre.org/)  — ELF / PE (EXE/DLL) / Mach-O -> symbol export

Design constraints
------------------
* Uploaded programs are NEVER executed.  JADX and Ghidra operate as static
  analysis tools only; both run in their own contained subprocess with strict
  resource bounds.
* Tool availability is probed once at module import and cached.  If a tool is
  absent the adapter degrades gracefully, appending a disclosure note instead
  of failing the scan.
* All output is written to a temporary directory inside the per-scan work/
  folder and is cleaned up by the caller.
* Subprocess timeouts (JADX 120 s, Ghidra 300 s) prevent runaway scans.
* Output is capped at MAX_DECOMPILE_FILES discovered Java/pseudocode sources.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resource bounds
# ---------------------------------------------------------------------------
JADX_TIMEOUT_SECONDS = 120
GHIDRA_TIMEOUT_SECONDS = 300
MAX_DECOMPILE_FILES = 200
MAX_DECOMPILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MiB

# ---------------------------------------------------------------------------
# Crypto patterns applied to decompiled source text
# ---------------------------------------------------------------------------
_CRYPTO_PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    ("RSA",      re.compile(rb"(?i)\bRSA\b")),
    ("AES",      re.compile(rb"(?i)\bAES\b")),
    ("3DES",     re.compile(rb"(?i)\b(?:3DES|DESede|TripleDES)\b")),
    ("DES",      re.compile(rb"(?i)(?<!\d)\bDES\b(?!ede)")),
    ("ECDSA",    re.compile(rb"(?i)\bECDSA\b")),
    ("ECDH",     re.compile(rb"(?i)\bECDH\b")),
    ("DSA",      re.compile(rb"(?i)(?<!ML-)(?<!ML_)(?<!SLH-)(?<!SLH_)\bDSA\b")),
    ("MD5",      re.compile(rb"(?i)\bMD5\b")),
    ("SHA-1",    re.compile(rb"(?i)\bSHA[-_]?1\b")),
    ("SHA-256",  re.compile(rb"(?i)\bSHA[-_]?256\b")),
    ("ChaCha20", re.compile(rb"(?i)\bChaCha20\b")),
    ("RC4",      re.compile(rb"(?i)\b(?:RC4|ARC4)\b")),
    ("ML-KEM",   re.compile(rb"(?i)\b(?:ML[-_]?KEM|Kyber)\b")),
    ("ML-DSA",   re.compile(rb"(?i)\bML[-_]?DSA\b")),
    ("SLH-DSA",  re.compile(rb"(?i)\bSLH[-_]?DSA\b")),
    ("Ed25519",  re.compile(rb"(?i)\bEd25519\b")),
    ("X25519",   re.compile(rb"(?i)\bX25519\b")),
]

# Symbol-name substrings used for Ghidra output (no word-boundary — algo names
# are often embedded inside longer identifiers like EVP_aes_256_gcm or SHA256_Init).
_SYMBOL_ALGO_SUBSTRINGS: list[tuple[str, list[str]]] = [
    ("AES",      ["aes", "_aes_", "AES"]),
    ("RSA",      ["rsa", "_rsa_", "RSA"]),
    ("ECDSA",    ["ecdsa", "ECDSA"]),
    ("ECDH",     ["ecdh", "ECDH"]),
    ("DSA",      ["_dsa_", "DSA"]),
    ("MD5",      ["md5", "MD5"]),
    ("SHA-1",    ["sha1", "sha_1", "SHA1", "SHA_1"]),
    ("SHA-256",  ["sha256", "sha_256", "SHA256", "SHA_256"]),
    ("SHA-512",  ["sha512", "sha_512", "SHA512", "SHA_512"]),
    ("3DES",     ["3des", "desede", "tripledes", "3DES", "DESede", "TripleDES"]),
    ("DES",      ["_des_", "DES_"]),
    ("RC4",      ["rc4", "arc4", "RC4", "ARC4"]),
    ("ChaCha20", ["chacha20", "ChaCha20"]),
    ("ML-KEM",   ["ml_kem", "ml-kem", "mlkem", "kyber", "ML_KEM", "Kyber"]),
    ("ML-DSA",   ["ml_dsa", "ml-dsa", "mldsa", "ML_DSA"]),
    ("SLH-DSA",  ["slh_dsa", "slh-dsa", "slhdsa", "SLH_DSA"]),
    ("Ed25519",  ["ed25519", "Ed25519"]),
    ("X25519",   ["x25519", "X25519"]),
    ("BCryptEncrypt", ["BCryptEncrypt", "BCryptCreateHash", "CryptEncrypt"]),
]


def _match_symbol_name(sym_name: str) -> list[str]:
    """Return algorithm labels matched by substring in a binary symbol name."""
    matched: list[str] = []
    for algorithm, substrings in _SYMBOL_ALGO_SUBSTRINGS:
        for sub in substrings:
            if sub in sym_name:
                matched.append(algorithm)
                break
    return matched


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

@dataclass
class ToolInfo:
    available: bool
    path: str
    version: str


def _probe_jadx() -> ToolInfo:
    candidate = shutil.which("jadx") or os.environ.get("JADX_PATH", "")
    if not candidate:
        return ToolInfo(available=False, path="", version="")
    try:
        result = subprocess.run(
            [candidate, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        version = (result.stdout.strip() or result.stderr.strip())[:120]
        return ToolInfo(available=True, path=candidate, version=version)
    except Exception as exc:
        logger.debug("jadx probe failed: %s", exc)
        return ToolInfo(available=False, path=candidate, version="")


def _probe_ghidra() -> ToolInfo:
    candidate = (
        shutil.which("analyzeHeadless")
        or os.environ.get("GHIDRA_HEADLESS", "")
    )
    if not candidate:
        return ToolInfo(available=False, path="", version="")
    try:
        result = subprocess.run(
            [candidate, "--help"],
            capture_output=True, text=True, timeout=15,
        )
        m = re.search(r"Ghidra\s+[\d.]+", result.stdout + result.stderr)
        version = m.group(0) if m else "Ghidra (version unknown)"
        return ToolInfo(available=True, path=candidate, version=version[:120])
    except Exception as exc:
        logger.debug("ghidra probe failed: %s", exc)
        return ToolInfo(available=False, path=candidate, version="")


# Probed once per process start
JADX_INFO: ToolInfo = _probe_jadx()
GHIDRA_INFO: ToolInfo = _probe_ghidra()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PRIORITY_MAP = {
    "MD5": "review", "SHA-1": "review", "DES": "review",
    "3DES": "review", "RC4": "review",
    "RSA": "review", "ECDSA": "review", "ECDH": "review", "DSA": "review",
}


def _priority(algorithm: str) -> str:
    return _PRIORITY_MAP.get(algorithm, "info")


def _recommendation(algorithm: str) -> str:
    if _priority(algorithm) == "review":
        if algorithm in {"RSA", "ECDSA", "ECDH", "DSA"}:
            return (
                "Review long-lived data encrypted with this algorithm "
                "and plan a post-quantum migration."
            )
        return (
            "Review and replace security-sensitive uses of this legacy "
            "algorithm with a modern alternative."
        )
    return "Check configuration and key management."


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class DecompileResult:
    tool: str
    tool_version: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    decompiled_files: int = 0
    decompiled_lines: int = 0


def _scan_source_bytes(
    data: bytes, location: str, tool: str
) -> list[dict[str, Any]]:
    findings = []
    for algorithm, pattern in _CRYPTO_PATTERNS:
        m = pattern.search(data)
        if m:
            start = max(0, m.start() - 40)
            end = min(len(data), m.end() + 40)
            snippet = (
                data[start:end]
                .decode("utf-8", errors="replace")
                .replace("\n", " ")
                .strip()
            )
            findings.append(dict(
                algorithm=algorithm,
                location=location,
                line=data[: m.start()].count(b"\n") + 1,
                evidence=f"Decompiled source ({tool})",
                priority=_priority(algorithm),
                recommendation=_recommendation(algorithm),
                snippet=snippet[:200],
            ))
    return findings


# ---------------------------------------------------------------------------
# JADX adapter
# ---------------------------------------------------------------------------

def run_jadx(input_path: Path, work_dir: Path) -> DecompileResult:
    """Decompile APK / DEX / JAR with JADX and scan resulting Java source."""
    result = DecompileResult(tool="jadx", tool_version=JADX_INFO.version)

    if not JADX_INFO.available:
        result.tool = "unavailable"
        result.limitations.append(
            "JADX is not installed. APK/DEX/JAR decompilation is unavailable; "
            "string indicators were used instead. "
            "Install JADX to enable full decompilation."
        )
        return result

    if input_path.stat().st_size > MAX_DECOMPILE_SIZE_BYTES:
        result.limitations.append(
            f"Input file exceeds the {MAX_DECOMPILE_SIZE_BYTES // (1024 * 1024)} MiB "
            "JADX limit; decompilation skipped."
        )
        return result

    out_dir = work_dir / "jadx-output"
    out_dir.mkdir(exist_ok=True)

    cmd = [
        JADX_INFO.path,
        "--no-res",
        "--no-imports",
        "--output-dir", str(out_dir),
        str(input_path),
    ]
    logger.info("Running JADX: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=JADX_TIMEOUT_SECONDS,
            cwd=str(work_dir),
        )
        if proc.returncode not in (0, 1):
            stderr_snippet = proc.stderr[-500:].decode("utf-8", errors="replace")
            result.limitations.append(
                f"JADX exited with code {proc.returncode}. "
                f"Output may be partial. stderr: {stderr_snippet}"
            )
    except subprocess.TimeoutExpired:
        result.limitations.append(
            f"JADX timed out after {JADX_TIMEOUT_SECONDS}s. "
            "Results represent partial decompilation only."
        )
    except Exception as exc:
        result.limitations.append(f"JADX invocation failed: {exc}")
        logger.warning("JADX failed for %s: %s", input_path, exc)
        return result

    java_files = sorted(out_dir.rglob("*.java"))[:MAX_DECOMPILE_FILES]
    result.decompiled_files = len(java_files)
    if len(java_files) == MAX_DECOMPILE_FILES:
        result.limitations.append(
            f"Only the first {MAX_DECOMPILE_FILES} decompiled Java files were scanned."
        )

    for java_file in java_files:
        try:
            data = java_file.read_bytes()
            result.decompiled_lines += data.count(b"\n")
            rel = str(java_file.relative_to(out_dir)).replace("\\", "/")
            result.findings.extend(
                _scan_source_bytes(data, f"[decompiled]/{rel}", "jadx")
            )
        except Exception as exc:
            logger.debug("Could not read decompiled file %s: %s", java_file, exc)

    if not java_files:
        result.limitations.append(
            "JADX produced no Java source files. The APK/JAR may be heavily "
            "obfuscated or use unsupported DEX features. "
            "String indicators remain in the report."
        )

    return result


# ---------------------------------------------------------------------------
# Ghidra adapter
# ---------------------------------------------------------------------------

_GHIDRA_SCRIPT_CONTENT = """\
// ExportCryptoSymbols.java — Ghidra headless script for ECDAT
// Emits function names and imports matching crypto patterns to stdout.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import java.util.regex.*;

public class ExportCryptoSymbols extends GhidraScript {
    private static final Pattern CRYPTO_RE = Pattern.compile(
        "(?i)\\\\b(AES|RSA|ECDSA|ECDH|DES|3DES|DESede|MD5|SHA1|SHA256|SHA512|" +
        "ChaCha20|RC4|ARC4|ML.?KEM|Kyber|ML.?DSA|SLH.?DSA|Ed25519|X25519|" +
        "EVP_aes|EVP_des|EVP_rsa|EVP_ec|BCryptEncrypt|BCryptCreateHash|" +
        "CryptEncrypt|CryptCreateHash|SecretKeySpec|Cipher|MessageDigest|" +
        "KeyPairGenerator|crypto_secretbox|crypto_sign|OQS_KEM|OQS_SIG)\\\\b"
    );

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        for (Function f : fm.getFunctions(true)) {
            String name = f.getName();
            if (CRYPTO_RE.matcher(name).find()) {
                println("FUNC:" + f.getEntryPoint() + ":" + name);
            }
        }
        SymbolTable st = currentProgram.getSymbolTable();
        for (Symbol sym : st.getExternalSymbols()) {
            String name = sym.getName();
            if (CRYPTO_RE.matcher(name).find()) {
                println("IMPORT:" + name);
            }
        }
    }
}
"""

_GHIDRA_SCRIPT_NAME = "ExportCryptoSymbols.java"
GHIDRA_EXTENSIONS = {".elf", ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a", ".sys"}


def run_ghidra(input_path: Path, work_dir: Path) -> DecompileResult:
    """Analyze a native binary with Ghidra headless and extract crypto symbols."""
    result = DecompileResult(tool="ghidra", tool_version=GHIDRA_INFO.version)

    if not GHIDRA_INFO.available:
        result.tool = "unavailable"
        result.limitations.append(
            "Ghidra is not installed. Native binary symbol analysis is unavailable; "
            "string indicators were used instead. "
            "Install Ghidra to enable deep symbol extraction."
        )
        return result

    if input_path.stat().st_size > MAX_DECOMPILE_SIZE_BYTES:
        result.limitations.append(
            f"Input file exceeds the {MAX_DECOMPILE_SIZE_BYTES // (1024 * 1024)} MiB "
            "Ghidra limit; analysis skipped."
        )
        return result

    script_dir = work_dir / "ghidra-scripts"
    script_dir.mkdir(exist_ok=True)
    (script_dir / _GHIDRA_SCRIPT_NAME).write_text(
        _GHIDRA_SCRIPT_CONTENT, encoding="utf-8"
    )

    project_dir = work_dir / "ghidra-project"
    project_dir.mkdir(exist_ok=True)

    cmd = [
        GHIDRA_INFO.path,
        str(project_dir),
        "ecdat_scan",
        "-import", str(input_path),
        "-postScript", _GHIDRA_SCRIPT_NAME,
        "-scriptPath", str(script_dir),
        "-deleteProject",
        "-noanalysis",
        "-readOnly",
    ]
    logger.info("Running Ghidra: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=GHIDRA_TIMEOUT_SECONDS,
            cwd=str(work_dir),
        )
    except subprocess.TimeoutExpired:
        result.limitations.append(
            f"Ghidra timed out after {GHIDRA_TIMEOUT_SECONDS}s. "
            "Results may be incomplete."
        )
        return result
    except Exception as exc:
        result.limitations.append(f"Ghidra invocation failed: {exc}")
        logger.warning("Ghidra failed for %s: %s", input_path, exc)
        return result

    if proc.returncode != 0:
        stderr_snippet = proc.stderr[-300:].decode("utf-8", errors="replace")
        result.limitations.append(
            f"Ghidra exited with code {proc.returncode}. stderr: {stderr_snippet}"
        )

    output = proc.stdout.decode("utf-8", errors="replace")
    filename = input_path.name
    seen: set[tuple[str, str]] = set()

    for line in output.splitlines():
        line = line.strip()
        if not (line.startswith("FUNC:") or line.startswith("IMPORT:")):
            continue
        parts = line.split(":", 2)
        if line.startswith("FUNC:") and len(parts) == 3:
            _, addr, sym_name = parts
            location = f"{filename}@{addr}"
        else:
            sym_name = parts[-1]
            location = filename

        for algorithm in _match_symbol_name(sym_name):
            key = (algorithm, location)
            if key not in seen:
                seen.add(key)
                result.findings.append(dict(
                    algorithm=algorithm,
                    location=location,
                    line=None,
                    evidence=f"Ghidra symbol ({sym_name})",
                    priority=_priority(algorithm),
                    recommendation=_recommendation(algorithm),
                    snippet=sym_name[:200],
                ))

    result.decompiled_files = 1
    if not result.findings:
        result.limitations.append(
            "Ghidra found no crypto-related symbols/imports. "
            "The binary may be stripped, packed, or use custom APIs "
            "not covered by current patterns."
        )

    return result


# ---------------------------------------------------------------------------
# Public dispatch
# ---------------------------------------------------------------------------

def decompile_and_scan(
    input_path: Path, kind: str, work_dir: Path
) -> DecompileResult:
    """Select and run the appropriate decompiler for the given file type.

    Args:
        input_path: Absolute path to the uploaded binary/archive.
        kind:       ECDAT scan kind: ``'apk'``, ``'exe'``, ``'library'``, etc.
        work_dir:   Per-scan working directory for tool output.

    Returns:
        DecompileResult with findings, limitations, and tool provenance.
    """
    suffix = input_path.suffix.lower()

    if kind == "apk" or suffix in {".apk", ".dex", ".aar"}:
        return run_jadx(input_path, work_dir)

    if suffix == ".jar" or (kind == "library" and suffix in {".jar", ".aar", ".zip"}):
        return run_jadx(input_path, work_dir)

    if suffix in GHIDRA_EXTENSIONS or kind == "exe":
        return run_ghidra(input_path, work_dir)

    if kind == "library":
        return run_ghidra(input_path, work_dir)

    return DecompileResult(
        tool="unavailable",
        tool_version="",
        limitations=[
            f"No decompiler is configured for extension '{suffix}' / kind '{kind}'. "
            "String indicators were used."
        ],
    )


def tool_status() -> dict[str, Any]:
    """Return installed decompiler availability for operator inspection."""
    return {
        "jadx": {
            "available": JADX_INFO.available,
            "path": JADX_INFO.path,
            "version": JADX_INFO.version,
        },
        "ghidra": {
            "available": GHIDRA_INFO.available,
            "path": GHIDRA_INFO.path,
            "version": GHIDRA_INFO.version,
        },
    }
