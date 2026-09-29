"""Run inside the built image with --network none; uploaded code is not executed."""
import hashlib
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

import importlib.util
if importlib.util.find_spec('ecdat') is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ecdat.apps.api.routers.uploads import perform_scan, now


def verify(root: Path):
    expected = json.loads((root / 'QuantumReady-DemoCorp/ground-truth.json').read_text())['cases']
    for filename, kind in [('QuantumReady-DemoCorp.zip', 'source'), ('QuantumReady-DemoCorp-container.tar', 'container')]:
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            data = (root / filename).read_bytes()
            (folder / 'original').write_bytes(data)
            record = dict(id=str(uuid.uuid4()), filename=filename, kind=kind, created_at=now(),
                          sha256=hashlib.sha256(data).hexdigest(), context={
                              'protection_lifetime_years': 10, 'migration_years': 3, 'quantum_horizon_years': 10,
                              'criticality': 'critical', 'sensitivity': 'restricted', 'exposure': 'external'})
            perform_scan(folder, record)
            assert record['status'] == 'completed'
            if kind == 'source':
                actual = {(f['location'], f['algorithm']) for f in record['findings']}
                missing = {(case['file'], algorithm) for case in expected for algorithm in case['expected']} - actual
                assert not missing, missing
            assert all((folder / name).is_file() for name in ['cbom.json', 'cbom-1.7.json', 'results.sarif', 'findings.csv', 'checksums.json'])
            print(f"PASS {filename}: {record['finding_count']} findings; validated exports; coverage {record['coverage']['status']}")
    if hasattr(os, 'getuid'):
        assert os.getuid() != 0, 'Production demo must run as non-root'
        print(f'PASS non-root UID {os.getuid()}')


if __name__ == '__main__':
    verify(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1])
