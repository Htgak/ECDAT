"""Acquire repository snapshots and safely flatten saved container images."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tarfile
import time
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

MAX_BYTES = 500 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_ENTRIES = 5000


def safe_name(name: str) -> str:
    path = PurePosixPath(name.replace('\\', '/'))
    if path.is_absolute() or '..' in path.parts or ':' in name or '\x00' in name:
        raise ValueError('Archive contains an unsafe path.')
    return str(path)


def run_tool(args: list[str], folder: Path, *, timeout: int = 180, limit: int = MAX_BYTES,
             output: Path | None = None, env: dict | None = None) -> int:
    """No shell, bounded elapsed time and output directory; terminate child group."""
    output = output or folder / 'tool.log'
    with output.open('wb') as log:
        proc = subprocess.Popen(args, stdout=log, stderr=subprocess.DEVNULL, env=env,
                                start_new_session=os.name != 'nt')
        start = time.monotonic()
        try:
            while True:
                total = 0
                for path in folder.rglob('*'):
                    try:
                        if path.is_file() and not path.is_symlink():
                            total += path.stat().st_size
                    except FileNotFoundError:
                        pass  # Git atomically renames temporary packs during acquisition.
                if time.monotonic() - start > timeout or total > limit:
                    raise ValueError('Tool exceeded its time or output-size limit. Scan a smaller input.')
                if proc.poll() is not None:
                    break
                time.sleep(0.25)
            return proc.returncode
        finally:
            if proc.poll() is None:
                if os.name == 'nt':
                    subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                else:
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()


def validate_repository(url: str, ref: str) -> str:
    parsed = urlsplit(url)
    allowed = {'github.com', 'gitlab.com', 'bitbucket.org'}
    if (parsed.scheme != 'https' or parsed.hostname not in allowed or parsed.port not in (None, 443)
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or any(part in {'.', '..'} for part in parsed.path.split('/'))
            or not re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+/?', parsed.path)):
        raise ValueError('Use a public HTTPS repository on GitHub, GitLab, or Bitbucket without credentials.')
    if ref and (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,199}', ref)
                or '..' in ref or '@{' in ref):
        raise ValueError('Use a branch or tag name without special Git expressions.')
    return url.rstrip('/')


def repository_snapshot(folder: Path, url: str, ref: str) -> dict:
    url = validate_repository(url, ref)
    if not shutil.which('git'):
        raise ValueError('Git is not installed on this scanner.')
    work = folder / 'checkout'
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0',
               GIT_LFS_SKIP_SMUDGE='1')
    command = ['git', '-c', 'credential.helper=', '-c', 'http.followRedirects=false',
               '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
               'clone', '--depth', '1', '--single-branch', '--no-checkout', '--no-local']
    if ref:
        command += ['--branch', ref]
    try:
        if run_tool(command + ['--', url, str(work)], folder, env=env):
            raise ValueError('Repository could not be fetched. Check that the URL and branch are public and exist.')
        commit = subprocess.check_output(['git', '-C', str(work), 'rev-parse', 'HEAD'], env=env, timeout=10).decode().strip()
        if run_tool(['git', '-C', str(work), 'archive', '--format=zip', 'HEAD'], folder,
                    output=folder / 'original', env=env, limit=MAX_EXPANDED):
            raise ValueError('Repository snapshot could not be created.')
        if (folder / 'original').stat().st_size > MAX_BYTES:
            raise ValueError('Repository snapshot exceeds 500 MB.')
        with (folder / 'original').open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        return {'commit': commit, 'sha256': digest, 'size': (folder / 'original').stat().st_size,
                'tools': [{'name': 'Git', 'status': 'completed', 'purpose': 'Shallow clone and immutable source snapshot'}]}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def container_snapshot(source: Path, folder: Path) -> tuple[Path, list[str]]:
    """Docker save, single-image OCI layout or rootfs TAR. Never run image code.

    Whiteouts are applied in layer order. Links and devices are omitted, counted
    and disclosed. All reads are bounded; tarfile.extract is never used.
    """
    unpack = folder / 'image-input'
    root = folder / 'image-root'
    unpack.mkdir(); root.mkdir()
    budget = [0, 0, 0]

    def extract(path: Path, dest: Path, layer: bool = False) -> None:
        # Whiteouts affect only lower layers, regardless of TAR member order.
        if layer:
            with tarfile.open(path, 'r:*') as archive:
                expanded = 0
                for index, member in enumerate(archive):
                    expanded += member.size
                    if index >= MAX_ENTRIES or member.size < 0 or member.size > MAX_BYTES or expanded > MAX_EXPANDED:
                        raise ValueError('Container layer exceeds entry or expansion limits.')
                    name = safe_name(member.name)
                    target = dest / name
                    if target.name.startswith('.wh.'):
                        victim = target.parent if target.name == '.wh..wh..opq' else target.with_name(target.name[4:])
                        if not victim.resolve().is_relative_to(dest.resolve()):
                            raise ValueError('Unsafe container whiteout.')
                        if victim.exists():
                            if victim.is_dir(): shutil.rmtree(victim)
                            else: victim.unlink()
        with tarfile.open(path, 'r:*') as archive:
            seen: set[str] = set()
            for member in archive:
                budget[0] += 1; budget[1] += member.size
                if budget[0] > MAX_ENTRIES or budget[1] > MAX_EXPANDED or member.size > MAX_BYTES or member.size < 0:
                    raise ValueError('Container archive exceeds 5,000 entries, 500 MB per file, or 2 GB expanded.')
                name = safe_name(member.name)
                if name == '.' and not member.isdir():
                    raise ValueError('Container archive contains an invalid root entry.')
                if name in seen:
                    raise ValueError('Container archive contains duplicate paths.')
                seen.add(name)
                target = dest / name
                if not target.resolve().is_relative_to(dest.resolve()):
                    raise ValueError('Unsafe container path.')
                if layer and target.name.startswith('.wh.'):
                    continue
                if member.isdir():
                    if target.is_file(): target.unlink()
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    if target.is_dir(): shutil.rmtree(target)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    stream = archive.extractfile(member)
                    if stream is not None:
                        with stream, target.open('wb') as output:
                            shutil.copyfileobj(stream, output, 1024 * 1024)
                else:
                    if target.exists():
                        if target.is_dir(): shutil.rmtree(target)
                        else: target.unlink()
                    budget[2] += 1

    try:
        extract(source, unpack)
        layers: list[str] = []
        def read_manifest(path: Path):
            if path.stat().st_size > 1024 * 1024:
                raise ValueError('Container manifest exceeds 1 MiB.')
            return json.loads(path.read_text(encoding='utf-8'))
        if (unpack / 'manifest.json').is_file():
            manifests = read_manifest(unpack / 'manifest.json')
            if len(manifests) != 1:
                raise ValueError('Save one container image per archive.')
            layers = manifests[0]['Layers']
        elif (unpack / 'oci-layout').is_file():
            index = read_manifest(unpack / 'index.json')
            if len(index['manifests']) != 1:
                raise ValueError('Save a single-platform OCI image.')
            def blob(digest: str) -> str:
                if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
                    raise ValueError('Unsupported OCI digest.')
                name = 'blobs/sha256/' + digest.split(':')[1]
                with (unpack / name).open('rb') as stream:
                    if hashlib.file_digest(stream, 'sha256').hexdigest() != digest.split(':')[1]:
                        raise ValueError('OCI blob digest mismatch.')
                return name
            manifest = read_manifest(unpack / blob(index['manifests'][0]['digest']))
            layers = [blob(item['digest']) for item in manifest['layers']]
        if layers:
            for layer in layers:
                extract(unpack / safe_name(layer), root, layer=True)
        else:
            shutil.rmtree(root)
            unpack.rename(root)
        zipped = folder / 'container-source.zip'
        with zipfile.ZipFile(zipped, 'w', zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(root.rglob('*')):
                if path.is_file(): archive.write(path, path.relative_to(root).as_posix())
        return zipped, [f'Container filesystem inspection; {budget[2]} links/devices were omitted. Image code was not executed.']
    except (tarfile.TarError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        raise ValueError('Invalid or unsupported saved container image.') from exc
    finally:
        shutil.rmtree(unpack, ignore_errors=True)
        shutil.rmtree(root, ignore_errors=True)
