"""Migration suggestions from saved findings, without invented schedules."""
from __future__ import annotations

from copy import deepcopy
from typing import Any
from fastapi import APIRouter, HTTPException, Query
from starlette.concurrency import run_in_threadpool
from ecdat.apps.api.auth.dependencies import CurrentUser
from ecdat.core.discovery.assessment import enrich

router = APIRouter()


def suggestion(finding: dict, scan: dict) -> dict:
    item = deepcopy(finding)
    enrich([item], scan.get('context', {}))
    return {
        'id': scan['id'] + ':' + item['id'],
        'scan_id': scan['id'], 'filename': scan['filename'],
        'classical_algorithm': item['algorithm'],
        'pqc_replacement': ' / '.join(item['alternatives']) or 'Configuration review required',
        'alternatives': item['alternatives'], 'recommendation': item['recommendation'],
        'rationale': item['recommendation'], 'tradeoffs': item['tradeoffs'],
        'location': item['location'], 'evidence': item['evidence'],
        'standard': 'See referenced standards' if item['references'] else 'Use-case review',
        'references': item['references'], 'transition_tier': 'REVIEW',
        'target_deadline': None, 'estimated_effort_weeks': None, 'fips_standard': None,
    }


@router.get('/advisories')
async def get_advisories(current_user: CurrentUser, algorithm: str | None = Query(None)):
    algo_filter = algorithm if isinstance(algorithm, str) else None

    from ecdat.apps.api.routers.workspace import records
    tenant_id = str(current_user.id)
    results = []
    for scan in await run_in_threadpool(records, tenant_id):
        if scan.get('status') != 'completed':
            continue
        for finding in scan.get('findings', []):
            if not algo_filter or finding['algorithm'].casefold() == algo_filter.casefold():
                results.append(suggestion(finding, scan))
    if algo_filter:
        if not results:
            raise HTTPException(404, 'No saved discovery finding for this algorithm.')
        return results[0]
    return results
