"""Exercise retained offline collectors through real report generation."""
import json
import pytest
from ecdat.apps.cli.main import _run_local_scan, _export_report

@pytest.mark.asyncio
async def test_full_e2e_pipeline(tmp_path):
    code = 'import hashlib\ndigest = hashlib.md5(b"test").hexdigest()\n'
    (tmp_path/'one.py').write_text(code)
    (tmp_path/'two.py').write_text(code)
    report = await _run_local_scan(str(tmp_path))
    md5 = [f for f in report['findings'] if f['algorithm']=='MD5']
    assert len(md5)==2
    assert md5[0]['stable_id'] != md5[1]['stable_id']
    cbom=json.loads(_export_report(report,'cyclonedx'))
    sarif=json.loads(_export_report(report,'sarif'))
    assert cbom['specVersion']=='1.6'
    assert len(cbom['components'])==len(report['findings'])
    assert len(sarif['runs'][0]['results'])==len(report['findings'])
