"""File-first static crypto discovery with durable local artifacts.

Uploaded programs are never executed. Binary results are string indicators,
not proof of runtime cryptographic use. Storage uses the evidence volume.
"""
from __future__ import annotations

import asyncio
import codecs
import csv
import hashlib
import json
import logging
import re
import shutil
import stat
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Literal

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, ValidationError
from ecdat.core.discovery.assessment import RiskContext, enrich, write_standard_reports
from ecdat.core.discovery.metadata import discover, METADATA_EXTENSIONS
from ecdat.core.discovery.policies import evaluate as evaluate_policies, POLICY_VERSION
from ecdat.core.discovery.inputs import repository_snapshot, validate_repository, container_snapshot
from ecdat.collectors.binary.decompiler import decompile_and_scan, tool_status as decompiler_tool_status
from starlette.concurrency import run_in_threadpool

from ecdat.apps.api.config import get_settings
from ecdat.apps.api.auth.dependencies import CurrentUser
from ecdat.collectors.base import CollectorInput
from ecdat.collectors.source.java.scanner import JavaSourceScanner
from ecdat.collectors.source.python.scanner import PythonSourceScanner

router = APIRouter()
logger = logging.getLogger(__name__)
MAX_UPLOAD = 500 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_MEMBER = MAX_UPLOAD
MAX_AST_FILE = 32 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
MAX_FILES = 5000
MAX_FINDINGS = 5000
SOURCE_EXTENSIONS = {'.py', '.java', '.js', '.ts', '.jsx', '.tsx', '.c', '.cpp', '.h', '.cs', '.go', '.rs', '.kt', '.swift', '.php', '.rb'}
SCAN_SLOTS = threading.BoundedSemaphore(2)
ADMISSION = threading.BoundedSemaphore(8)
PATTERNS = [
    ('ECDH', rb'(?<![a-z0-9])ecdh(?![a-z0-9])'),
    ('DSA', rb'(?<![a-z0-9])(?<!ml-)(?<!ml_)(?<!slh-)(?<!slh_)dsa(?![a-z0-9])'),
    ('DH', rb'(?<![a-z0-9])dh(?![a-z0-9])'),
    ('Ed25519', rb'(?<![a-z0-9])ed25519(?![a-z0-9])'),
    ('X25519', rb'(?<![a-z0-9])x25519(?![a-z0-9])'),
    ('ML-DSA', rb'(?<![a-z0-9])ml[-_]?dsa(?![a-z0-9])'),
    ('SLH-DSA', rb'(?<![a-z0-9])slh[-_]?dsa(?![a-z0-9])'),
    ('MD5', rb'(?<![a-z0-9])md5(?![a-z0-9])'),
    ('SHA-1', rb'(?<![a-z0-9])sha[-_]?1(?![a-z0-9])'),
    ('3DES', rb'(?<![a-z0-9])(?:3des|tripledes|desede)(?![a-z0-9])'),
    ('DES', rb'(?<![a-z0-9])des(?![a-z0-9])'),
    ('RC4', rb'(?<![a-z0-9])(?:rc4|arc4)(?![a-z0-9])'),
    ('RSA', rb'(?<![a-z0-9])rsa(?![a-z0-9])'),
    ('ECDSA', rb'(?<![a-z0-9])ecdsa(?![a-z0-9])'),
    ('AES', rb'(?<![a-z0-9])aes(?![a-z0-9])'),
    ('SHA-256', rb'(?<![a-z0-9])sha[-_]?256(?![a-z0-9])'),
    ('ChaCha20', rb'(?<![a-z0-9])chacha20(?![a-z0-9])'),
    ('ML-KEM', rb'(?<![a-z0-9])(?:ml[-_]?kem|kyber)(?![a-z0-9])'),
]


def storage_root(tenant_id: str | None = None) -> Path:
    base = Path(get_settings().evidence_store_path) / 'uploads'
    if tenant_id:
        root = base / str(tenant_id)
    else:
        root = base
    root.mkdir(parents=True, exist_ok=True)
    return root


def record_paths(tenant_id: str):
    yield from storage_root(tenant_id).glob('*/record.json')
    if tenant_id == '00000000-0000-0000-0000-000000000001':
        yield from storage_root().glob('*/record.json')


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_record(folder: Path, record: dict[str, Any]) -> None:
    temporary = folder / 'record.tmp'
    temporary.write_text(json.dumps(record, indent=2), encoding='utf-8')
    temporary.replace(folder / 'record.json')


def read_record(scan_id: uuid.UUID, tenant_id: str | None = None) -> tuple[Path, dict[str, Any]]:
    folder = storage_root(tenant_id) / str(scan_id)
    if tenant_id == '00000000-0000-0000-0000-000000000001' and not (folder / 'record.json').exists():
        folder = storage_root() / str(scan_id)
    try:
        return folder, json.loads((folder / 'record.json').read_text(encoding='utf-8'))
    except FileNotFoundError:
        raise HTTPException(404, 'Scan not found.') from None
    except (OSError, ValueError):
        logger.warning('Unreadable scan record: %s', scan_id)
        raise HTTPException(503, 'Saved scan record is unreadable. Restore it from backup.') from None


def recover_interrupted() -> None:
    """A restart must never leave a persisted scan spinning indefinitely.

    Walks both the legacy root and all per-tenant subdirectories.
    """
    base = Path(get_settings().evidence_store_path) / 'uploads'
    # Collect all record.json files at depth 1 (legacy) and depth 2 (tenant-scoped)
    patterns = ['*/record.json', '*/*/record.json']
    for pattern in patterns:
        for path in base.glob(pattern):
            try:
                record = json.loads(path.read_text(encoding='utf-8'))
                if record['status'] in ('queued', 'scanning'):
                    record.update(
                        status='failed',
                        error='Scanning was interrupted. Upload the saved original file to try again.',
                        completed_at=now(),
                    )
                    save_record(path.parent, record)
            except (OSError, ValueError, KeyError):
                logger.exception('Could not recover upload record')


def archive_members(path: Path, kind: str) -> list[zipfile.ZipInfo]:
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > MAX_FILES or sum(m.file_size for m in members) > MAX_EXPANDED:
                raise ValueError('Archive is too large. Use at most 5,000 files and 2 GB unpacked.')
            names: set[str] = set()
            for member in members:
                name = member.filename.replace('\\', '/')
                parts = PurePosixPath(name)
                if parts.is_absolute() or '..' in parts.parts or ':' in name or '\x00' in name:
                    raise ValueError('Archive contains an unsafe file path.')
                if stat.S_ISLNK(member.external_attr >> 16) or member.flag_bits & 1:
                    raise ValueError('Encrypted archives and symbolic links are not supported.')
                if member.file_size > MAX_MEMBER:
                    raise ValueError('An archive file exceeds the 500 MB per-file limit.')
                key = str(parts).casefold()
                if key in names:
                    raise ValueError('Archive contains duplicate file paths.')
                names.add(key)
            if kind == 'apk' and 'AndroidManifest.xml' not in archive.namelist():
                raise ValueError('This file is not an APK: AndroidManifest.xml is missing.')
            return members
    except (zipfile.BadZipFile, NotImplementedError) as exc:
        raise ValueError('The archive is invalid or uses unsupported compression.') from exc


def validate_file(path: Path, kind: str, suffix: str) -> None:
    if kind in {'container', 'library'}:
        return
    if kind == 'apk' or suffix == '.zip':
        archive_members(path, kind)
    elif kind == 'exe':
        with path.open('rb') as stream:
            header = stream.read(64)
            if len(header) < 64 or header[:2] != b'MZ':
                raise ValueError('Choose a valid Windows EXE file.')
            offset = int.from_bytes(header[60:64], 'little')
            if offset < 64 or offset > path.stat().st_size - 24:
                raise ValueError('The EXE header is invalid.')
            stream.seek(offset)
            if stream.read(4) != b'PE\x00\x00':
                raise ValueError('The EXE header is invalid.')
    elif path.stat().st_size > MAX_MEMBER:
        raise ValueError('A source file must be smaller than 500 MB.')
    else:
        try:
            decoder = codecs.getincrementaldecoder('utf-8-sig')()
            with path.open('rb') as stream:
                while content := stream.read(CHUNK_SIZE):
                    decoder.decode(content)
                    if b'\x00' in content:
                        raise ValueError('Choose a UTF-8 source file or a ZIP of source files.')
            decoder.decode(b'', final=True)
        except UnicodeError as exc:
            raise ValueError('Source files must use UTF-8 encoding.') from exc


def recommendation(algorithm: str) -> tuple[str, str]:
    normalized = algorithm.upper().replace('_', '-').replace('TRIPLEDES', '3DES')
    if normalized in {'MD5', 'SHA1', 'SHA-1', 'DES', '3DES', 'DESEDE', 'RC4', 'ARC4'}:
        return 'review', 'Review this legacy algorithm and replace security-sensitive uses with a suitable modern alternative.'
    if normalized in {'RSA', 'ECDSA', 'EC', 'DSA', 'DH', 'ECDH'}:
        return 'review', 'Review long-lived data and plan an appropriate post-quantum migration.'
    return 'info', 'Check configuration and key management. Detection alone does not establish security.'


def indicator_findings(data: bytes, location: str) -> list[dict[str, Any]]:
    # Search ASCII and UTF-16LE strings without executing or decompiling binaries.
    views = [data.lower(), data.replace(b'\x00', b'').lower()]
    findings = []
    for algorithm, pattern in PATTERNS:
        if any(re.search(pattern, view) for view in views):
            priority, advice = recommendation(algorithm)
            findings.append(dict(algorithm=algorithm, location=location, line=None, evidence='String indicator', priority=priority, recommendation=advice))
    return findings


def indicator_stream(stream: BinaryIO, location: str) -> list[dict[str, Any]]:
    """Scan bounded chunks, retaining context across ASCII and UTF-16 boundaries."""
    found: set[str] = set()
    metadata = stream.read(CHUNK_SIZE)
    stream.seek(0)
    tails = [b'', b'']
    processed = [0, 0]
    while True:
        chunk = stream.read(CHUNK_SIZE)
        eof = not chunk
        views = [chunk.lower(), chunk.replace(b'\x00', b'').lower()]
        for index, view in enumerate(views):
            data = tails[index] + view
            for algorithm, pattern in PATTERNS:
                if algorithm in found:
                    continue
                for match in re.finditer(pattern, data):
                    at_stream_start = processed[index] == len(tails[index])
                    if (at_stream_start or match.start() > 0) and (eof or match.end() <= len(data) - 128):
                        found.add(algorithm)
                        break
            tails[index] = data[-256:]
            processed[index] += len(view)
        if eof:
            break
    findings = discover(metadata, location)
    modes = re.findall(rb'(?i)AES[-_/](?:\d+[-_/])?(GCM|CBC|ECB|CTR|CCM)', metadata)
    for algorithm, _ in PATTERNS:
        if algorithm in found:
            priority, advice = recommendation(algorithm)
            findings.append(dict(algorithm=algorithm, location=location, line=None, evidence='String indicator', priority=priority, recommendation=advice,
                                 mode=modes[0].decode().upper() if algorithm == 'AES' and modes else None))
    return findings


def perform_scan(folder: Path, record: dict[str, Any]) -> None:
    record.update(status='scanning')
    save_record(folder, record)
    source = folder / 'original'
    work = folder / 'work'
    work.mkdir(exist_ok=True)
    findings: list[dict[str, Any]] = []
    skipped = 0
    inspected = 0
    source_count = 0
    limitations: list[str] = []
    kind, suffix = record['kind'], Path(record['filename']).suffix.lower()
    if kind == 'git':
        kind = 'source'
        limitations.append('Snapshot of one Git revision. Submodules and Git LFS objects are not fetched; repository code is never executed.')
    if kind == 'container':
        source, notes = container_snapshot(source, folder)
        limitations.extend(notes)
        suffix = '.zip'
    if kind == 'exe' or kind == 'library' and suffix not in {'.jar', '.zip'}:
        with source.open('rb') as stream:
            findings.extend(indicator_stream(stream, record['filename']))
        inspected = 1
        # -------------------------------------------------------------------
        # Decompiler integration: JADX (APK/JAR) or Ghidra (ELF/EXE/DLL)
        # -------------------------------------------------------------------
        decomp_work = folder / 'decompile-work'
        decomp_work.mkdir(exist_ok=True)
        try:
            dr = decompile_and_scan(
                input_path=source,
                kind=kind,
                work_dir=decomp_work,
            )
            for df in dr.findings:
                priority_val, advice = recommendation(df['algorithm'])
                findings.append(dict(
                    algorithm=df['algorithm'],
                    location=df['location'],
                    line=df.get('line'),
                    evidence=df['evidence'],
                    priority=priority_val,
                    recommendation=advice,
                    mode=None,
                    key_size=None,
                    curve=None,
                    provider=None,
                    operation=None,
                    padding=None,
                ))
            limitations.extend(dr.limitations)
            record['decompilation_report'] = {
                'tool': dr.tool,
                'tool_version': dr.tool_version,
                'decompiled_files': dr.decompiled_files,
                'decompiled_lines': dr.decompiled_lines,
                'findings_from_decompiler': len(dr.findings),
                'limitations': dr.limitations,
            }
        except Exception as _de:
            logger.warning('Decompiler step failed: %s', _de)
            limitations.append(f'Decompiler step failed: {_de}. String indicators were used.')
            record['decompilation_report'] = {'tool': 'error', 'error': str(_de)}
        finally:
            shutil.rmtree(decomp_work, ignore_errors=True)
    else:
        if kind == 'apk' or suffix in {'.zip', '.jar'}:
            members = archive_members(source, kind)
            # -------------------------------------------------------------------
            # Decompiler integration for APK / JAR archives
            # -------------------------------------------------------------------
            decomp_work = folder / 'decompile-work'
            decomp_work.mkdir(exist_ok=True)
            try:
                dr = decompile_and_scan(
                    input_path=source,
                    kind=kind,
                    work_dir=decomp_work,
                )
                for df in dr.findings:
                    priority_val, advice = recommendation(df['algorithm'])
                    findings.append(dict(
                        algorithm=df['algorithm'],
                        location=df['location'],
                        line=df.get('line'),
                        evidence=df['evidence'],
                        priority=priority_val,
                        recommendation=advice,
                        mode=None, key_size=None, curve=None,
                        provider=None, operation=None, padding=None,
                    ))
                limitations.extend(dr.limitations)
                record['decompilation_report'] = {
                    'tool': dr.tool,
                    'tool_version': dr.tool_version,
                    'decompiled_files': dr.decompiled_files,
                    'decompiled_lines': dr.decompiled_lines,
                    'findings_from_decompiler': len(dr.findings),
                    'limitations': dr.limitations,
                }
            except Exception as _de:
                logger.warning('Decompiler step failed: %s', _de)
                limitations.append(f'Decompiler step failed: {_de}.')
                record['decompilation_report'] = {'tool': 'error', 'error': str(_de)}
            finally:
                shutil.rmtree(decomp_work, ignore_errors=True)
            with zipfile.ZipFile(source) as archive:
                for member in members:
                    if member.is_dir():
                        continue
                    extension = PurePosixPath(member.filename).suffix.lower()
                    if extension not in SOURCE_EXTENSIONS | METADATA_EXTENSIONS and kind == 'source':
                        skipped += 1
                        continue
                    inspected += 1
                    if extension in {'.py', '.java'} and kind == 'source' and member.file_size <= MAX_AST_FILE:
                        target = (work / member.filename.replace('\\', '/')).with_suffix(extension)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with archive.open(member) as stream, target.open('wb') as output:
                            shutil.copyfileobj(stream, output, CHUNK_SIZE)
                        source_count += 1
                    else:
                        with archive.open(member) as stream:
                            findings.extend(indicator_stream(stream, member.filename))
                        if kind == 'source' and extension in {'.py', '.java'}:
                            limitations.append(f'{member.filename}: over 32 MB; inspected for string indicators instead of parsing source.')
                    if len(findings) >= MAX_FINDINGS:
                        limitations.append('The 5,000 finding limit was reached; remaining files were not inspected.')
                        break
        else:
            inspected = 1
            if suffix in {'.py', '.java'} and source.stat().st_size <= MAX_AST_FILE:
                shutil.copyfile(source, work / ('input' + suffix))
                source_count = 1
            else:
                with source.open('rb') as stream:
                    findings.extend(indicator_stream(stream, record['filename']))
                if suffix in {'.py', '.java'}:
                    limitations.append('Source file exceeds 32 MB; inspected for string indicators instead of parsing source.')

        if source_count:
            async def collect() -> None:
                for scanner in (PythonSourceScanner(), JavaSourceScanner()):
                    result = await scanner.scan(CollectorInput(scan_id=record['id'], collector_run_id=str(uuid.uuid4()), tenant_id='local-upload-workspace', target_path=str(work)))
                    if result.is_partial or result.errors or result.unsupported_reason:
                        limitations.append(f'{scanner.name}: some files could not be fully analyzed.')
                    for envelope in result.envelopes:
                        observation = envelope.observation
                        algorithm = observation.algorithm or observation.algorithm_raw
                        if not algorithm:
                            continue
                        location = envelope.source_location
                        priority, advice = recommendation(algorithm)
                        finding_path = location.path.replace('\\', '/') if location and suffix == '.zip' else record['filename']
                        findings.append(dict(algorithm=algorithm, location=finding_path, line=location.line if location else None, evidence='Source observation', priority=priority, recommendation=advice, **{key: getattr(observation, key) for key in ['mode', 'key_size', 'curve', 'provider', 'operation', 'padding']}))
            asyncio.run(collect())

    if not inspected:
        raise ValueError('No supported source files were found in this archive.')
    # Multiple source rules can describe the same call; show one review item.
    unique = {(f['algorithm'], f['location'], f['line'], f['evidence'], f.get('name'), f.get('version'), f.get('fingerprint'),
               f.get('mode'), f.get('key_size'), f.get('operation')): f for f in findings}
    findings = list(unique.values())
    if len(findings) > MAX_FINDINGS:
        limitations.append('Only the first 5,000 findings are included.')
    findings = findings[:MAX_FINDINGS]
    findings.sort(key=lambda finding: (finding['priority'] != 'review', finding['algorithm'], finding['location']))
    if kind in {'apk', 'exe'}:
        limitations.append('Static string inspection only. Packed, obfuscated, and runtime-loaded code may hide cryptography. Indicators do not confirm use.')
    else:
        limitations.append('Python and Java use source analysis; other supported languages use string indicators. This scan does not prove the code is secure.')
    limitations.append('Metadata parsing is limited to the first 1 MiB per file. Versions, modes and key sizes remain unknown unless observed. Business context is supplied for the application and inherited by its findings.')
    record['assessment'] = enrich(findings, record.get('context', {}))
    record['assessment_version'] = 1
    record['policies'] = evaluate_policies(findings, record['id'])
    record['policy_version'] = POLICY_VERSION
    record.update(status='completed', completed_at=now(), findings=findings, finding_count=len(findings), review_count=sum(f['priority'] == 'review' for f in findings), inspected_files=inspected, skipped_files=skipped, limitations=limitations)
    (folder / 'report.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
    with (folder / 'findings.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=['algorithm', 'asset_type', 'version', 'mode', 'key_size', 'priority', 'quantum_status', 'risk_score', 'context', 'mosca', 'evidence', 'location', 'line', 'recommendation', 'tradeoffs'], extrasaction='ignore')
        writer.writeheader()
        for finding in findings:
            # Prevent spreadsheet formula interpretation of uploaded file names.
            writer.writerow({k: "'" + v if isinstance(v, str) and v.startswith(('=', '+', '-', '@', '\t', '\r')) else v for k, v in finding.items()})
    write_standard_reports(folder, record)
    save_record(folder, record)
    shutil.rmtree(work, ignore_errors=True)


def run_scan(folder: Path, record: dict[str, Any]) -> None:
    try:
        with SCAN_SLOTS:
            if record['kind'] == 'git':
                record.update(status='scanning', stage='Fetching repository')
                save_record(folder, record)
                record.update(repository_snapshot(folder, record['repository_url'], record['ref']))
                record.update(stage='Analyzing source', snapshot_ready=True)
                save_record(folder, record)
            perform_scan(folder, record)
    except Exception as exc:
        logger.exception('Upload scan failed: %s', record['id'])
        record.update(status='failed', completed_at=now(), error=str(exc) if isinstance(exc, ValueError) else 'The file could not be scanned. Try uploading it again.')
        save_record(folder, record)
    finally:
        shutil.rmtree(folder / 'work', ignore_errors=True)
        (folder / 'container-source.zip').unlink(missing_ok=True)
        ADMISSION.release()


class RepositoryRequest(BaseModel):
    url: str = Field(min_length=1, max_length=1000)
    ref: str = Field('', max_length=200)
    context: RiskContext = Field(default_factory=RiskContext)


@router.post('/uploads/repository', status_code=202)
def repository_scan(request: RepositoryRequest, background: BackgroundTasks, user: CurrentUser) -> dict[str, Any]:
    tenant_id = str(user.id)
    try:
        url = validate_repository(request.url.strip(), request.ref.strip())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not ADMISSION.acquire(blocking=False):
        raise HTTPException(429, 'The scanner is busy. Try again shortly.')
    folder = None
    try:
        folder = storage_root(tenant_id) / str(uuid.uuid4())
        folder.mkdir()
        filename = url.rsplit('/', 1)[-1].removesuffix('.git') + '.zip'
        record = dict(id=folder.name, tenant_id=tenant_id, filename=filename, kind='git', context=request.context.model_dump(exclude_unset=True), repository_url=url, ref=request.ref.strip(),
                      size=0, sha256=None, snapshot_ready=False, status='queued', created_at=now(), completed_at=None,
                      finding_count=0, review_count=0, findings=[], limitations=[], error=None)
        save_record(folder, record)
        background.add_task(run_scan, folder, record.copy())
        return record
    except Exception:
        ADMISSION.release()
        if folder is not None:
            shutil.rmtree(folder, ignore_errors=True)
        raise


@router.post('/uploads', status_code=202)
async def upload_scan(background: BackgroundTasks, user: CurrentUser, kind: Literal['apk', 'exe', 'source', 'library', 'container'] = Form(...), file: UploadFile = File(...), context: str = Form('{}')) -> dict[str, Any]:
    tenant_id = str(user.id)
    try:
        planning = RiskContext.model_validate_json(context).model_dump(exclude_unset=True)
    except ValidationError as exc:
        raise HTTPException(422, 'Invalid assessment context: use finite, non-negative lifetimes and a positive quantum horizon.') from exc
    filename = (file.filename or 'upload').replace('\\', '/').split('/')[-1]
    filename = re.sub(r'[\x00-\x1f\x7f]', '', filename)[:180]
    suffix = Path(filename).suffix.lower()
    allowed = {'.tar', '.gz', '.tgz'} if kind == 'container' else {'.so', '.dll', '.dylib', '.a', '.jar', '.zip'} if kind == 'library' else {'.apk'} if kind == 'apk' else {'.exe'} if kind == 'exe' else SOURCE_EXTENSIONS | {'.zip'}
    if suffix not in allowed:
        raise HTTPException(400, 'The selected file does not match the input type.')
    if not ADMISSION.acquire(blocking=False):
        raise HTTPException(429, 'The scanner is busy. Try again shortly.')
    folder: Path | None = None
    queued = False
    try:
        folder = storage_root(tenant_id) / str(uuid.uuid4())
        folder.mkdir()
        size = 0
        digest = hashlib.sha256()
        with (folder / 'original').open('wb') as output:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(413, 'Choose a file up to 500 MB.')
                digest.update(chunk)
                output.write(chunk)
        if not size:
            raise HTTPException(400, 'The file is empty.')
        try:
            await run_in_threadpool(validate_file, folder / 'original', kind, suffix)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        record = dict(id=folder.name, tenant_id=tenant_id, filename=filename, kind=kind, context=planning, size=size, sha256=digest.hexdigest(), status='queued', created_at=now(), completed_at=None, finding_count=0, review_count=0, findings=[], limitations=[], error=None)
        save_record(folder, record)
        background.add_task(run_scan, folder, record.copy())
        queued = True
        return record
    finally:
        await file.close()
        if not queued:
            ADMISSION.release()
            if folder is not None and folder.exists():
                shutil.rmtree(folder)


@router.get('/uploads/decompiler-status')
def decompiler_status() -> dict[str, Any]:
    """Return installed decompiler tool availability for operator inspection."""
    return decompiler_tool_status()


@router.get('/uploads')
def list_uploads(user: CurrentUser) -> list[dict[str, Any]]:
    tenant_id = str(user.id)
    records = []
    for path in record_paths(tenant_id):
        try:
            record = json.loads(path.read_text(encoding='utf-8'))
            record.pop('findings', None)
            records.append(record)
        except (OSError, ValueError):
            logger.warning('Unreadable scan record: %s', path.parent.name)
            raise HTTPException(503, 'A saved scan record is unreadable. Check server logs and restore it from backup.') from None
    return sorted(records, key=lambda record: record['created_at'], reverse=True)


@router.get('/uploads/config')
def upload_config() -> dict[str, int]:
    return {'max_upload_bytes': MAX_UPLOAD, 'max_expanded_bytes': MAX_EXPANDED}


@router.get('/uploads/{scan_id}')
def upload_result(scan_id: uuid.UUID, user: CurrentUser) -> dict[str, Any]:
    return read_record(scan_id, str(user.id))[1]


@router.get('/uploads/{scan_id}/artifacts/{artifact}')
def download_artifact(scan_id: uuid.UUID, artifact: Literal['original', 'report', 'findings', 'cbom', 'sarif', 'checksums'], user: CurrentUser) -> FileResponse:
    folder, record = read_record(scan_id, str(user.id))
    names = {'original': ('original', record['filename'], 'application/octet-stream'), 'report': ('report.json', 'scan-report.json', 'application/json'), 'findings': ('findings.csv', 'findings.csv', 'text/csv')}
    names.update(cbom=('cbom.json', 'cbom.cdx.json', 'application/json'), sarif=('results.sarif', 'results.sarif', 'application/json'), checksums=('checksums.json', 'checksums.json', 'application/json'))
    name, filename, media_type = names[artifact]
    if artifact == 'original' and record['kind'] == 'git' and not record.get('snapshot_ready'):
        raise HTTPException(409, 'The repository snapshot is not available.')
    if artifact != 'original' and record['status'] != 'completed':
        raise HTTPException(409, 'The report is not ready yet.')
    if not (folder / name).is_file():
        raise HTTPException(404, 'Artifact not found.')
    return FileResponse(folder / name, filename=filename, media_type=media_type, headers={'X-Content-Type-Options': 'nosniff'})
