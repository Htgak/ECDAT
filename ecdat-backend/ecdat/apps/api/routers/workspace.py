"""One read model for the saved scans used by every workspace screen."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import csv
import io
import json
import uuid
import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from ecdat.apps.api.auth.dependencies import CurrentUser
from ecdat.apps.api.routers.uploads import storage_root, record_paths, read_record
from ecdat.core.discovery.assessment import enrich, standard_documents
from ecdat.core.discovery.policies import evaluate

router = APIRouter(prefix='/workspace')


def records(tenant_id: str | None = None) -> list[dict]:
    result = []
    seen_ids = set()
    paths = record_paths(tenant_id) if tenant_id else storage_root().glob('*/record.json')
    for path in paths:
        try:
            scan = json.loads(path.read_text(encoding='utf-8'))
            scan_id = uuid.UUID(scan['id'])
            if scan_id in seen_ids:
                continue
            if scan['status'] not in {'queued', 'scanning', 'completed', 'failed'} or not isinstance(scan['created_at'], str):
                raise ValueError('Invalid scan state')
            if scan['status'] == 'completed':
                scan['findings'] = deepcopy(scan.get('findings', []))
                enrich(scan['findings'], scan.get('context', {}))
            result.append(scan)
            seen_ids.add(scan_id)
        except (ValueError, KeyError, OSError, TypeError) as exc:
            logging.getLogger(__name__).exception('Unreadable scan record: %s', path.parent.name)
            raise HTTPException(503, 'A saved scan record is unreadable. Check server logs and restore that record from backup.') from exc
    return sorted(result, key=lambda scan: scan['created_at'], reverse=True)


def asset_rows(scans: list[dict]) -> list[dict]:
    result = []
    for scan in scans:
        if scan['status'] != 'completed':
            continue
        for f in scan['findings']:
            ident = str(uuid.uuid5(uuid.UUID(scan['id']), f['id']))
            verdict = f.get('mosca', {}).get('verdict')
            result.append(dict(id=ident, stable_id=f['id'], scan_id=scan['id'],
                               asset_type=f['asset_type'].upper(), algorithm=f['algorithm'],
                               key_size=f.get('key_size'), curve=f.get('curve'), provider=f.get('provider'),
                               confidence=f['confidence'].upper(), analysis_status='OBSERVED',
                               usage_evidence=f['evidence'], created_at=scan['created_at'],
                               qars_score=f.get('risk_score'), score_model='discovery-planning-v1',
                               mosca_verdict='safe' if verdict == 'within_horizon' else verdict,
                               repository=scan.get('repository_url') or scan['filename'], occurrences_count=1,
                               exposure=f.get('context', {}).get('exposure', '').upper() or None,
                               criticality=f.get('context', {}).get('criticality', '').upper() or None,
                               finding=f, filename=scan['filename']))
    return result


@router.get('/assets')
def assets(current_user: CurrentUser, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
           algorithm: str | None = None, confidence: str | None = None):
    rows = asset_rows(records(str(current_user.id)))
    rows = [row for row in rows if (not algorithm or row['algorithm'].casefold() == algorithm.casefold())
            and (not confidence or row['confidence'].casefold() == confidence.casefold())]
    return {'items': rows[(page - 1) * page_size:page * page_size], 'total': len(rows),
            'page': page, 'page_size': page_size, 'pages': max(1, (len(rows) + page_size - 1) // page_size)}


@router.get('/assets/{asset_id}')
def asset(asset_id: uuid.UUID, current_user: CurrentUser):
    for row in asset_rows(records(str(current_user.id))):
        if row['id'] == str(asset_id):
            return row
    raise HTTPException(404, 'Finding not found in completed scans.')


@router.get('/scans')
def scans(current_user: CurrentUser):
    t_id = str(current_user.id)
    return [dict(id=s['id'], repository_id=s['id'], repository_name=s['filename'],
                 status={'queued': 'PENDING', 'scanning': 'RUNNING', 'completed': 'COMPLETED', 'failed': 'FAILED'}[s['status']],
                 commit_ref=s.get('commit'), completed_at=s.get('completed_at'), created_at=s['created_at'],
                 is_complete=s['status'] == 'completed', asset_count=s.get('finding_count', 0),
                 act_now_count=sum(f.get('mosca', {}).get('verdict') == 'act_now' for f in s.get('findings', []))) for s in records(t_id)]


@router.get('/policies')
def policies(current_user: CurrentUser):
    t_id = str(current_user.id)
    return [result for scan in records(t_id) if scan['status'] == 'completed'
            for result in (scan.get('policies') if scan.get('policy_version') == '1.0.0' else None)
            or evaluate(scan['findings'], scan['id'])]


@router.get('/evidence')
def evidence(current_user: CurrentUser):
    t_id = str(current_user.id)
    return [dict(id=s['id'], filename=s['filename'], sha256=s.get('sha256'),
                 status=s['status'], completed_at=s.get('completed_at'),
                 checksums_available=(read_record(uuid.UUID(s['id']), t_id)[0] / 'checksums.json').is_file()) for s in records(t_id)]


@router.get('/export/{format}')
def export(format: Literal['cyclonedx', 'sarif', 'csv'], current_user: CurrentUser):
    t_id = str(current_user.id)
    rows = asset_rows(records(t_id))
    findings = [{**row['finding'], 'id': row['id'], 'scan_id': row['scan_id'], 'source_filename': row['filename']} for row in rows]
    if format == 'cyclonedx':
        content = json.dumps(standard_documents({'id': str(uuid.uuid4()), 'completed_at': datetime.now(timezone.utc).isoformat(),
                             'filename': 'Saved scan inventory', 'findings': findings})[0], indent=2)
        filename = 'workspace.cdx.json'
    elif format == 'sarif':
        content = json.dumps(standard_documents({'id': str(uuid.uuid4()), 'completed_at': datetime.now(timezone.utc).isoformat(),
                             'filename': 'Saved scan inventory', 'findings': findings})[1], indent=2)
        filename = 'workspace.sarif'
    else:
        stream = io.StringIO(newline='')
        fields = ['scan_id', 'algorithm', 'asset_type', 'repository', 'confidence', 'qars_score', 'mosca_verdict']
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow({key: "'" + value if isinstance(value, str) and value.startswith(('=', '+', '-', '@', '\t', '\r')) else value for key, value in row.items()})
        content, filename = stream.getvalue(), 'workspace.csv'
    return Response(content, media_type='text/csv' if format == 'csv' else 'application/json',
                    headers={'Content-Disposition': f'attachment; filename="{filename}"', 'X-Content-Type-Options': 'nosniff'})
