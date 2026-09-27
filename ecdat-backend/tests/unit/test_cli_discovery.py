import json
from typer.testing import CliRunner
from ecdat.apps.cli.main import app


def test_exports_keep_real_findings(tmp_path):
    source = tmp_path / 'scan.json'
    source.write_text(json.dumps({'findings': [{'algorithm': 'RSA', 'location': 'crypto.py', 'evidence': 'Source observation'}]}))
    for fmt in ['cyclonedx', 'sarif']:
        target = tmp_path / (fmt + '.json')
        result = CliRunner().invoke(app, ['export', str(source), '--format', fmt, '-o', str(target)])
        assert result.exit_code == 0, result.output
        report = json.loads(target.read_text())
        assert len(report['components'] if fmt == 'cyclonedx' else report['runs'][0]['results']) == 1


def test_gate_respects_threshold_and_incomplete_scans(tmp_path):
    source = tmp_path / 'scan.json'
    source.write_text(json.dumps({'findings': [{'algorithm': 'RSA', 'location': 'crypto.py', 'evidence': 'Source observation'}]}))
    runner = CliRunner()
    assert runner.invoke(app, ['gate', str(source)]).exit_code == 3
    assert runner.invoke(app, ['gate', str(source), '--fail-on', 'warn']).exit_code == 1
    assert runner.invoke(app, ['gate', str(source), '--policy', 'fips']).exit_code == 2
    source.write_text(json.dumps({'status': 'failed', 'findings': []}))
    assert runner.invoke(app, ['gate', str(source)]).exit_code == 3
