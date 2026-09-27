"""Offline local scanning, real-finding exports, baseline gates.

Gate exits: 0 applicable checks pass; 1 violation; 2 invalid input; 3 indeterminate.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(
    name="ecdat",
    help="Enterprise Cryptographic Discovery & Analysis Tool",
    add_completion=False,
    no_args_is_help=True,
)


# ──────────────────────────────────────────────────────────────────────────── #
# ecdat scan                                                                    #
# ──────────────────────────────────────────────────────────────────────────── #

@app.command("scan")
def cmd_scan(
    target: Path = typer.Argument(..., help="Local source directory to scan"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file (JSON)"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json | cyclonedx | sarif"),
    no_deps: bool = typer.Option(False, "--no-deps", help="Skip dependency scanning"),
    no_source: bool = typer.Option(False, "--no-source", help="Skip source code scanning"),
    commit: Optional[str] = typer.Option(None, "--commit", help="Provenance label only; does not check out a commit"),
) -> None:
    """Scan a local path for cryptographic assets."""
    typer.echo(f"Scanning: {target}", err=True)

    try:
        result = asyncio.run(_run_local_scan(
            target=str(target),
            include_source=not no_source,
            include_deps=not no_deps,
            commit_ref=commit,
        ))

        output_data = _export_report(result, format)

        if output:
            output.write_text(output_data, encoding="utf-8")
            typer.echo(f"Results written to {output}")
        else:
            typer.echo(output_data)

        findings_count = result.get("total_findings", 0)
        typer.echo(f"\n✓ Scan complete: {findings_count} findings", err=True)

    except Exception as exc:
        typer.echo(f"✗ Scan failed: {exc}", err=True)
        raise typer.Exit(code=2)


async def _run_local_scan(
    target: str,
    include_source: bool = True,
    include_deps: bool = True,
    commit_ref: str | None = None,
) -> dict:
    """Run scanners locally without a running API."""
    from ecdat.collectors.base import CollectorInput
    from ecdat.collectors.source.java.scanner import JavaSourceScanner
    from ecdat.collectors.source.python.scanner import PythonSourceScanner
    from ecdat.collectors.dependency.pypi import PyPIDependencyScanner
    from ecdat.collectors.dependency.npm import NpmDependencyScanner
    from ecdat.collectors.dependency.maven import MavenDependencyScanner
    from ecdat.collectors.dependency.gomod import GoModDependencyScanner
    import uuid

    if not Path(target).is_dir():
        raise ValueError("A local source directory is required. Use the repository API for Git URLs.")
    tenant_id = "cli-local-scan"
    scan_id = str(uuid.uuid4())
    collector_run_id = str(uuid.uuid4())

    inp = CollectorInput(
        scan_id=scan_id,
        collector_run_id=collector_run_id,
        tenant_id=tenant_id,
        target_path=target,
        commit_ref=commit_ref,
    )

    all_envelopes = []
    limitations = []

    if include_source:
        for scanner_cls in [JavaSourceScanner, PythonSourceScanner]:
            scanner = scanner_cls()
            result = await scanner.scan(inp)
            all_envelopes.extend(result.envelopes)
            if result.is_partial or result.errors or result.unsupported_reason:
                limitations.append(f"{scanner.name}: incomplete analysis")
            typer.echo(f"  {scanner.name}: {result.findings_count} findings", err=True)

    if include_deps:
        for scanner_cls in [PyPIDependencyScanner, NpmDependencyScanner, MavenDependencyScanner, GoModDependencyScanner]:
            scanner = scanner_cls()
            result = await scanner.scan(inp)
            all_envelopes.extend(result.envelopes)
            if result.is_partial or result.errors or result.unsupported_reason:
                limitations.append(f"{scanner.name}: incomplete analysis")
            if result.findings_count > 0:
                typer.echo(f"  {scanner.name}: {result.findings_count} findings", err=True)

    findings = []
    seen = set()
    for env in all_envelopes:
        if env.has_secret_content():
            limitations.append('Collector evidence containing secret metadata was omitted.')
            continue
        key = (env.observation.algorithm, _format_location(env), env.observation.mode, env.observation.key_size, env.observation.operation)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "algorithm": env.observation.algorithm,
            "observation_type": env.observation.observation_type.value if hasattr(env.observation.observation_type, "value") else str(env.observation.observation_type),
            "confidence": env.confidence.value if hasattr(env.confidence, "value") else str(env.confidence),
            "stable_id": __import__("hashlib").sha256(repr(key).encode()).hexdigest(),
            "location": _format_location(env),
        })
    confirmed = sum(1 for f in findings if f.get("confidence", "").lower() == "confirmed")
    probable = sum(1 for f in findings if f.get("confidence", "").lower() == "probable")
    unconfirmed = len(findings) - confirmed - probable

    return {
        "scan_id": scan_id,
        "target": target,
        "total_findings": len(findings),
        "confirmed": confirmed,
        "probable": probable,
        "unconfirmed": unconfirmed,
        "findings": findings,
        "is_partial": bool(limitations),
        "limitations": limitations,
    }


def _format_location(envelope) -> str:
    if envelope.source_location:
        loc = envelope.source_location
        return f"{loc.path}:{loc.line or '?'}"
    if envelope.dependency_location:
        loc = envelope.dependency_location
        return f"{loc.ecosystem}:{loc.package_name}@{loc.package_version}"
    if envelope.container_location:
        return envelope.container_location.image_reference
    return "unknown"


# ──────────────────────────────────────────────────────────────────────────── #
# ecdat gate                                                                    #
# ──────────────────────────────────────────────────────────────────────────── #

@app.command("gate")
def cmd_gate(
    scan_file: Path = typer.Argument(..., help="Path to scan output JSON"),
    policy: str = typer.Option("ecdat-baseline", "--policy", "-p", help="Policy pack name"),
    fail_on: str = typer.Option("fail", "--fail-on", help="Verdict to fail on: fail | warn"),
) -> None:
    """CI gate: evaluate policy and exit non-zero on violations.

    Exit codes:
      0 = all assets pass
      1 = policy violations found
      3 = indeterminate result
    """
    if not scan_file.exists():
        typer.echo(f"✗ Scan file not found: {scan_file}", err=True)
        raise typer.Exit(code=2)

    try:
        if policy != 'ecdat-baseline' or fail_on not in {'fail', 'warn'}:
            raise ValueError("Use --policy ecdat-baseline and --fail-on fail|warn.")
        scan_data = json.loads(scan_file.read_text(encoding='utf-8'))
        if scan_data.get('status') in {'queued', 'scanning', 'failed'} or scan_data.get('is_partial'):
            typer.echo('Indeterminate: scan did not complete full supported analysis.', err=True)
            raise typer.Exit(code=3)
        findings = _assessed_findings(scan_data)
        if not findings:
            typer.echo('Indeterminate: no findings to evaluate.', err=True)
            raise typer.Exit(code=3)
        from ecdat.core.discovery.policies import evaluate
        results = evaluate(findings, scan_data.get('id', scan_data.get('scan_id', 'cli')))
        violations = [r for r in results if r['verdict'] == 'fail' or fail_on == 'warn' and r['verdict'] == 'warn']
        if violations:
            for row in violations:
                typer.echo(f"[{row['rule_id']}] {row['asset_algorithm']}: {row['explanation']}")
            raise typer.Exit(code=1)
        if not results or any(r['verdict'] in {'unknown', 'warn'} for r in results):
            typer.echo('Indeterminate: findings require review or no baseline rule applies.', err=True)
            raise typer.Exit(code=3)
        typer.echo('Applicable ECDAT baseline checks passed; this is not a compliance certification.')

    except typer.Exit:
        raise
    except Exception as exc:
        typer.echo(f"✗ Gate error: {exc}", err=True)
        raise typer.Exit(code=2)



# ──────────────────────────────────────────────────────────────────────────── #
# ecdat verify                                                                  #
# ──────────────────────────────────────────────────────────────────────────── #

@app.command("server")
def cmd_server(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(False, "--reload"),
) -> None:
    """Start the ECDAT API server."""
    import uvicorn
    uvicorn.run(
        "ecdat.apps.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_config=None,
    )


# ──────────────────────────────────────────────────────────────────────────── #
# ecdat export                                                                  #
# ──────────────────────────────────────────────────────────────────────────── #

@app.command("export")
def cmd_export(
    scan_file: Path = typer.Argument(..., help="Scan output JSON file"),
    format: str = typer.Option("cyclonedx", "--format", "-f"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Export scan results to a specified format."""
    if not scan_file.exists():
        typer.echo(f"✗ Scan file not found: {scan_file}", err=True)
        raise typer.Exit(code=2)

    try:
        scan_data = json.loads(scan_file.read_text(encoding='utf-8'))
        result = _export_report(scan_data, format)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        typer.echo(f"Export failed: {exc}", err=True)
        raise typer.Exit(code=2)

    if output:
        output.write_text(result, encoding="utf-8")
        typer.echo(f"✓ Exported to {output}")
    else:
        typer.echo(result)


def _assessed_findings(scan_data: dict) -> list[dict]:
    from copy import deepcopy
    from ecdat.core.discovery.assessment import enrich
    findings = deepcopy(scan_data.get('findings', []))
    if not isinstance(findings, list):
        raise ValueError('findings must be a list.')
    for finding in findings:
        finding.setdefault('evidence', 'CLI collector observation')
        finding.setdefault('location', 'Not reported')
    enrich(findings, scan_data.get('context', {}))
    return findings


def _export_report(scan_data: dict, format: str) -> str:
    import uuid
    from datetime import datetime, timezone
    from ecdat.core.discovery.assessment import standard_documents
    if format == 'json':
        return json.dumps(scan_data, indent=2, default=str)
    if format not in {'cyclonedx', 'cbom', 'cyclonedx17', 'sarif'}:
        raise ValueError('Supported formats: json, cyclonedx, sarif')
    if format == 'cyclonedx17':
        typer.echo('cyclonedx17 is a legacy alias; export uses supported CycloneDX 1.6.', err=True)
    record = {'id': str(uuid.uuid4()), 'filename': scan_data.get('filename') or scan_data.get('target') or 'CLI scan',
              'completed_at': datetime.now(timezone.utc).isoformat(), 'findings': _assessed_findings(scan_data)}
    return json.dumps(standard_documents(record)[1 if format == 'sarif' else 0], indent=2)


if __name__ == "__main__":
    app()
