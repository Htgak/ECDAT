"""Identify the actual scanner source, including uncommitted edits."""
import hashlib
import os
import subprocess
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def build_provenance():
    package = Path(__file__).resolve().parents[2]
    digest = hashlib.sha256()
    for path in sorted(package.rglob('*')):
        if path.is_file() and path.suffix in {'.py', '.yaml', '.json'}:
            digest.update(path.relative_to(package).as_posix().encode())
            digest.update(path.read_bytes().replace(b'\r\n', b'\n'))
    commit = os.environ.get('ECDAT_GIT_COMMIT') or None
    if not commit:
        try:
            proc = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=package,
                                  capture_output=True, timeout=3, check=True, text=True)
            commit = proc.stdout.strip()[:40]
        except (OSError, subprocess.SubprocessError):
            pass
    return {'git_commit': commit, 'scanner_source_sha256': digest.hexdigest(),
            'revision_note': 'Source hash identifies these files; Git commit alone may exclude working-tree edits.'}
