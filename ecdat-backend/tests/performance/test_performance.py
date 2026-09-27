"""Bounded throughput check for the active assessment and report path."""
import time
from ecdat.core.discovery.assessment import enrich, standard_documents

def test_assessment_and_export_1000_observations():
    findings=[{'algorithm':'RSA','location':f'file-{i}.py','evidence':'Source observation'} for i in range(1000)]
    start=time.perf_counter()
    enrich(findings,{'data_lifetime_years':10,'migration_years':2,'quantum_horizon_years':8,'criticality':'high','sensitivity':'restricted','exposure':'external'})
    cbom,sarif=standard_documents({'id':'00000000-0000-0000-0000-000000000001','filename':'performance-fixture','completed_at':'2026-09-27T00:00:00Z','findings':findings})
    assert len(cbom['components'])==1000
    assert len(sarif['runs'][0]['results'])==1000
    assert all(f['mosca']['verdict']=='act_now' for f in findings)
    assert time.perf_counter()-start<2
