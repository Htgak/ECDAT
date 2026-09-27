"""Unit tests for ECDAT CLI."""

from __future__ import annotations

from pathlib import Path
from typer.testing import CliRunner

from ecdat.apps.cli.main import app

runner = CliRunner()


class TestCLI:
    def test_cli_help(self) -> None:
        res = runner.invoke(app, ["--help"])
        assert res.exit_code == 0
        assert "Enterprise Cryptographic Discovery & Analysis Tool" in res.output
        assert "scan" in res.output
        assert "export" in res.output
        assert "gate" in res.output

    def test_cli_scan_local_path(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("import hashlib\nh = hashlib.sha256(b'test')\n")
        out_file = tmp_path / "results.json"

        res = runner.invoke(app, ["scan", str(tmp_path), "--output", str(out_file)])
        assert res.exit_code == 0, res.output
        assert out_file.exists()

    def test_cli_scan_cyclonedx_format(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("import hashlib\nh = hashlib.sha256(b'test')\n")
        out_file = tmp_path / "cbom.json"

        res = runner.invoke(app, ["scan", str(tmp_path), "--format", "cyclonedx17", "--output", str(out_file)])
        assert res.exit_code == 0, res.output
        assert out_file.exists()
        assert "CycloneDX" in out_file.read_text()
