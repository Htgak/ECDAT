"""Unit tests for ecdat.collectors.binary.decompiler.

All tests mock subprocess.run so JADX/Ghidra need not be installed.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ecdat.collectors.binary.decompiler import (
    DecompileResult,
    JADX_TIMEOUT_SECONDS,
    GHIDRA_TIMEOUT_SECONDS,
    MAX_DECOMPILE_FILES,
    MAX_DECOMPILE_SIZE_BYTES,
    _priority,
    _recommendation,
    _scan_source_bytes,
    decompile_and_scan,
    run_jadx,
    run_ghidra,
    tool_status,
    ToolInfo,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_java_source(algorithms: list[str]) -> bytes:
    """Build a minimal fake decompiled Java file containing the given algo strings."""
    lines = ['public class Fake {']
    for alg in algorithms:
        lines.append(f'    Cipher.getInstance("{alg}");')
    lines.append('}')
    return '\n'.join(lines).encode('utf-8')


# ---------------------------------------------------------------------------
# _priority / _recommendation
# ---------------------------------------------------------------------------

class TestPriorityAndRecommendation:
    def test_rsa_is_review(self):
        assert _priority('RSA') == 'review'

    def test_md5_is_review(self):
        assert _priority('MD5') == 'review'

    def test_aes_is_info(self):
        assert _priority('AES') == 'info'

    def test_ml_kem_is_info(self):
        assert _priority('ML-KEM') == 'info'

    def test_rsa_recommendation_mentions_pqc(self):
        rec = _recommendation('RSA')
        assert 'post-quantum' in rec.lower()

    def test_md5_recommendation_mentions_replace(self):
        rec = _recommendation('MD5')
        assert 'replace' in rec.lower()

    def test_aes_recommendation_generic(self):
        rec = _recommendation('AES')
        assert 'configuration' in rec.lower()


# ---------------------------------------------------------------------------
# _scan_source_bytes
# ---------------------------------------------------------------------------

class TestScanSourceBytes:
    def test_detects_rsa(self):
        data = b'Cipher.getInstance("RSA");'
        findings = _scan_source_bytes(data, 'Test.java', 'jadx')
        algos = {f['algorithm'] for f in findings}
        assert 'RSA' in algos

    def test_detects_aes(self):
        data = b'SecretKeySpec key = new SecretKeySpec(bytes, "AES");'
        findings = _scan_source_bytes(data, 'Test.java', 'jadx')
        assert any(f['algorithm'] == 'AES' for f in findings)

    def test_evidence_contains_tool_name(self):
        data = b'MD5 hash'
        findings = _scan_source_bytes(data, 'x.java', 'jadx')
        assert any('jadx' in f['evidence'] for f in findings)

    def test_snippet_is_capped_at_200(self):
        data = b'A' * 500 + b'RSA' + b'B' * 500
        findings = _scan_source_bytes(data, 'x.java', 'jadx')
        for f in findings:
            assert len(f.get('snippet', '')) <= 200

    def test_no_findings_for_clean_file(self):
        data = b'public class Empty { void hello() {} }'
        assert _scan_source_bytes(data, 'Empty.java', 'jadx') == []

    def test_line_number_calculated(self):
        data = b'line1\nline2\nRSA here'
        findings = _scan_source_bytes(data, 'x.java', 'jadx')
        rsa = next(f for f in findings if f['algorithm'] == 'RSA')
        assert rsa['line'] == 3

    def test_pqc_ml_kem_detected(self):
        data = b'ML-KEM encapsulation key'
        findings = _scan_source_bytes(data, 'x.java', 'jadx')
        assert any(f['algorithm'] == 'ML-KEM' for f in findings)


# ---------------------------------------------------------------------------
# run_jadx — unavailable
# ---------------------------------------------------------------------------

class TestJadxUnavailable:
    def test_graceful_degradation(self, tmp_path):
        fake_file = tmp_path / 'app.apk'
        fake_file.write_bytes(b'\x00' * 100)

        with patch('ecdat.collectors.binary.decompiler.JADX_INFO',
                   ToolInfo(available=False, path='', version='')):
            result = run_jadx(fake_file, tmp_path)

        assert result.tool == 'unavailable'
        assert result.findings == []
        assert any('not installed' in lim for lim in result.limitations)

    def test_file_too_large_skipped(self, tmp_path):
        huge = tmp_path / 'big.apk'
        huge.write_bytes(b'\x00' * 10)

        with patch('ecdat.collectors.binary.decompiler.JADX_INFO',
                   ToolInfo(available=True, path='/usr/bin/jadx', version='1.5.1')), \
             patch('ecdat.collectors.binary.decompiler.MAX_DECOMPILE_SIZE_BYTES', 5):
            result = run_jadx(huge, tmp_path)

        assert result.findings == []
        assert any('exceeds' in lim for lim in result.limitations)


# ---------------------------------------------------------------------------
# run_jadx — subprocess mocked
# ---------------------------------------------------------------------------

class TestJadxWithMockedSubprocess:
    def _make_jadx_info(self):
        return ToolInfo(available=True, path='/usr/bin/jadx', version='1.5.1')

    def test_successful_decompilation_finds_rsa(self, tmp_path):
        fake_apk = tmp_path / 'app.apk'
        fake_apk.write_bytes(b'\x00' * 100)

        # Pre-create fake Java output that JADX "produced"
        out_dir = tmp_path / 'jadx-output'
        out_dir.mkdir()
        (out_dir / 'Main.java').write_bytes(_fake_java_source(['RSA', 'AES']))

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stderr = b''
        mock_proc.stdout = b''

        with patch('ecdat.collectors.binary.decompiler.JADX_INFO', self._make_jadx_info()), \
             patch('subprocess.run', return_value=mock_proc):
            result = run_jadx(fake_apk, tmp_path)

        algos = {f['algorithm'] for f in result.findings}
        assert 'RSA' in algos
        assert 'AES' in algos
        assert result.decompiled_files == 1

    def test_timeout_adds_limitation(self, tmp_path):
        fake_apk = tmp_path / 'app.apk'
        fake_apk.write_bytes(b'\x00' * 100)

        with patch('ecdat.collectors.binary.decompiler.JADX_INFO', self._make_jadx_info()), \
             patch('subprocess.run', side_effect=subprocess.TimeoutExpired('jadx', JADX_TIMEOUT_SECONDS)):
            result = run_jadx(fake_apk, tmp_path)

        assert any('timed out' in lim for lim in result.limitations)

    def test_no_java_output_adds_limitation(self, tmp_path):
        fake_apk = tmp_path / 'app.apk'
        fake_apk.write_bytes(b'\x00' * 100)

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stderr = b''
        mock_proc.stdout = b''

        with patch('ecdat.collectors.binary.decompiler.JADX_INFO', self._make_jadx_info()), \
             patch('subprocess.run', return_value=mock_proc):
            result = run_jadx(fake_apk, tmp_path)

        assert any('no Java source' in lim for lim in result.limitations)

    def test_non_zero_exit_adds_limitation(self, tmp_path):
        fake_apk = tmp_path / 'app.apk'
        fake_apk.write_bytes(b'\x00' * 100)

        mock_proc = MagicMock()
        mock_proc.returncode = 2
        mock_proc.stderr = b'error detail'
        mock_proc.stdout = b''

        with patch('ecdat.collectors.binary.decompiler.JADX_INFO', self._make_jadx_info()), \
             patch('subprocess.run', return_value=mock_proc):
            result = run_jadx(fake_apk, tmp_path)

        assert any('exited with code 2' in lim for lim in result.limitations)

    def test_max_files_cap_adds_limitation(self, tmp_path):
        fake_apk = tmp_path / 'app.apk'
        fake_apk.write_bytes(b'\x00' * 100)

        out_dir = tmp_path / 'jadx-output'
        out_dir.mkdir()
        # Create MAX_DECOMPILE_FILES + 5 Java files
        for i in range(MAX_DECOMPILE_FILES + 5):
            (out_dir / f'C{i}.java').write_bytes(b'// empty')

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stderr = b''
        mock_proc.stdout = b''

        with patch('ecdat.collectors.binary.decompiler.JADX_INFO', self._make_jadx_info()), \
             patch('subprocess.run', return_value=mock_proc):
            result = run_jadx(fake_apk, tmp_path)

        assert result.decompiled_files == MAX_DECOMPILE_FILES
        assert any('first' in lim for lim in result.limitations)


# ---------------------------------------------------------------------------
# run_ghidra — unavailable
# ---------------------------------------------------------------------------

class TestGhidraUnavailable:
    def test_graceful_degradation(self, tmp_path):
        fake_elf = tmp_path / 'lib.so'
        fake_elf.write_bytes(b'\x7fELF' + b'\x00' * 60)

        with patch('ecdat.collectors.binary.decompiler.GHIDRA_INFO',
                   ToolInfo(available=False, path='', version='')):
            result = run_ghidra(fake_elf, tmp_path)

        assert result.tool == 'unavailable'
        assert result.findings == []
        assert any('not installed' in lim for lim in result.limitations)


# ---------------------------------------------------------------------------
# run_ghidra — subprocess mocked
# ---------------------------------------------------------------------------

class TestGhidraWithMockedSubprocess:
    def _make_ghidra_info(self):
        return ToolInfo(available=True, path='/opt/tools/ghidra/support/analyzeHeadless', version='Ghidra 11.1.2')

    def test_parses_func_output(self, tmp_path):
        fake_elf = tmp_path / 'target.elf'
        fake_elf.write_bytes(b'\x7fELF' + b'\x00' * 60)

        stdout = b'FUNC:00401000:EVP_aes_256_gcm\nFUNC:00401100:SHA256_Init\n'
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = stdout
        mock_proc.stderr = b''

        with patch('ecdat.collectors.binary.decompiler.GHIDRA_INFO', self._make_ghidra_info()), \
             patch('subprocess.run', return_value=mock_proc):
            result = run_ghidra(fake_elf, tmp_path)

        algos = {f['algorithm'] for f in result.findings}
        assert 'AES' in algos
        assert 'SHA-256' in algos

    def test_parses_import_output(self, tmp_path):
        fake_elf = tmp_path / 'target.elf'
        fake_elf.write_bytes(b'\x7fELF' + b'\x00' * 60)

        stdout = b'IMPORT:RSA_public_encrypt\n'
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = stdout
        mock_proc.stderr = b''

        with patch('ecdat.collectors.binary.decompiler.GHIDRA_INFO', self._make_ghidra_info()), \
             patch('subprocess.run', return_value=mock_proc):
            result = run_ghidra(fake_elf, tmp_path)

        algos = {f['algorithm'] for f in result.findings}
        assert 'RSA' in algos

    def test_no_symbols_adds_limitation(self, tmp_path):
        fake_elf = tmp_path / 'stripped.elf'
        fake_elf.write_bytes(b'\x7fELF' + b'\x00' * 60)

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b''
        mock_proc.stderr = b''

        with patch('ecdat.collectors.binary.decompiler.GHIDRA_INFO', self._make_ghidra_info()), \
             patch('subprocess.run', return_value=mock_proc):
            result = run_ghidra(fake_elf, tmp_path)

        assert any('no crypto-related' in lim for lim in result.limitations)

    def test_timeout_adds_limitation(self, tmp_path):
        fake_elf = tmp_path / 'target.elf'
        fake_elf.write_bytes(b'\x7fELF' + b'\x00' * 60)

        with patch('ecdat.collectors.binary.decompiler.GHIDRA_INFO', self._make_ghidra_info()), \
             patch('subprocess.run', side_effect=subprocess.TimeoutExpired('analyzeHeadless', GHIDRA_TIMEOUT_SECONDS)):
            result = run_ghidra(fake_elf, tmp_path)

        assert any('timed out' in lim for lim in result.limitations)


# ---------------------------------------------------------------------------
# decompile_and_scan dispatch
# ---------------------------------------------------------------------------

class TestDecompileAndScanDispatch:
    def test_apk_dispatches_to_jadx(self, tmp_path):
        f = tmp_path / 'app.apk'
        f.write_bytes(b'\x00' * 10)

        with patch('ecdat.collectors.binary.decompiler.run_jadx') as mock_jadx, \
             patch('ecdat.collectors.binary.decompiler.run_ghidra') as mock_ghidra:
            mock_jadx.return_value = DecompileResult(tool='jadx', tool_version='1.5.1')
            decompile_and_scan(f, 'apk', tmp_path)

        mock_jadx.assert_called_once()
        mock_ghidra.assert_not_called()

    def test_exe_dispatches_to_ghidra(self, tmp_path):
        f = tmp_path / 'app.exe'
        f.write_bytes(b'MZ' + b'\x00' * 10)

        with patch('ecdat.collectors.binary.decompiler.run_jadx') as mock_jadx, \
             patch('ecdat.collectors.binary.decompiler.run_ghidra') as mock_ghidra:
            mock_ghidra.return_value = DecompileResult(tool='ghidra', tool_version='11.1.2')
            decompile_and_scan(f, 'exe', tmp_path)

        mock_ghidra.assert_called_once()
        mock_jadx.assert_not_called()

    def test_jar_dispatches_to_jadx(self, tmp_path):
        f = tmp_path / 'app.jar'
        f.write_bytes(b'PK' + b'\x00' * 10)

        with patch('ecdat.collectors.binary.decompiler.run_jadx') as mock_jadx, \
             patch('ecdat.collectors.binary.decompiler.run_ghidra') as mock_ghidra:
            mock_jadx.return_value = DecompileResult(tool='jadx', tool_version='1.5.1')
            decompile_and_scan(f, 'library', tmp_path)

        mock_jadx.assert_called_once()
        mock_ghidra.assert_not_called()

    def test_so_dispatches_to_ghidra(self, tmp_path):
        f = tmp_path / 'libcrypto.so'
        f.write_bytes(b'\x7fELF' + b'\x00' * 10)

        with patch('ecdat.collectors.binary.decompiler.run_jadx') as mock_jadx, \
             patch('ecdat.collectors.binary.decompiler.run_ghidra') as mock_ghidra:
            mock_ghidra.return_value = DecompileResult(tool='ghidra', tool_version='11.1.2')
            decompile_and_scan(f, 'library', tmp_path)

        mock_ghidra.assert_called_once()
        mock_jadx.assert_not_called()

    def test_unknown_type_returns_unavailable(self, tmp_path):
        f = tmp_path / 'data.bin'
        f.write_bytes(b'\x00' * 10)

        result = decompile_and_scan(f, 'source', tmp_path)
        assert result.tool == 'unavailable'
        assert result.findings == []


# ---------------------------------------------------------------------------
# tool_status
# ---------------------------------------------------------------------------

class TestToolStatus:
    def test_returns_both_tools(self):
        status = tool_status()
        assert 'jadx' in status
        assert 'ghidra' in status

    def test_each_tool_has_required_keys(self):
        status = tool_status()
        for tool in ('jadx', 'ghidra'):
            assert 'available' in status[tool]
            assert 'path' in status[tool]
            assert 'version' in status[tool]

    def test_available_is_bool(self):
        status = tool_status()
        assert isinstance(status['jadx']['available'], bool)
        assert isinstance(status['ghidra']['available'], bool)
