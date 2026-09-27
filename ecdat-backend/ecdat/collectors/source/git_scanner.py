"""Git repository manager and collector.

Provides:
- Git clone / checkout support for remote and local Git repositories.
- Commit metadata extraction (SHA, author, timestamp, message, branch).
- Incremental diff scanning (calculating changed files between scan revisions).
- Git repository cryptographic configuration and commit history discovery.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import structlog

from ecdat.collectors.base import (
    CollectorCapabilities,
    CollectorInput,
    CollectorInterface,
    CollectorResult,
)
from ecdat.core.evidence.envelope import (
    CollectorInfo,
    CryptoObservation,
    DetectionRule,
    EvidenceEnvelope,
    EvidenceFingerprint,
    RunInfo,
    SourceLocation,
)
from ecdat.core.model.types import (
    Confidence,
    ObservationType,
    UsageEvidence,
)

logger = structlog.get_logger(__name__)


def _run_git(args: list[str], cwd: str, timeout: int = 120) -> tuple[int, str, str]:
    """Execute a git command safely in a given working directory."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        logger.warning("git_command_failed", args=args, cwd=cwd, error=str(exc))
        return -1, "", str(exc)


class GitRepositoryManager:
    """Manages Git repository cloning, checkouts, and incremental diff queries."""

    @staticmethod
    def is_git_repo(path: str) -> bool:
        """Check if path is a valid git repository."""
        if not os.path.exists(path):
            return False
        ret, stdout, _ = _run_git(["rev-parse", "--is-inside-work-tree"], cwd=path)
        return ret == 0 and stdout == "true"

    @classmethod
    def clone_or_checkout(
        cls,
        repo_url_or_path: str,
        target_dir: str,
        commit_ref: str | None = None,
    ) -> dict[str, Any]:
        """Clone remote git repo or checkout branch/ref on existing local repo.

        Returns metadata about the cloned or prepared repository.
        """
        os.makedirs(target_dir, exist_ok=True)
        is_remote = any(
            repo_url_or_path.startswith(prefix)
            for prefix in ("http://", "https://", "git@", "ssh://", "git://")
        )

        if is_remote:
            # If repo already exists in target_dir, fetch; else clone
            if cls.is_git_repo(target_dir):
                logger.info("fetching_existing_repo", target_dir=target_dir)
                _run_git(["fetch", "--all"], cwd=target_dir)
            else:
                # Clean target_dir if non-empty
                if os.listdir(target_dir):
                    shutil.rmtree(target_dir)
                    os.makedirs(target_dir, exist_ok=True)

                logger.info("cloning_remote_repo", url=repo_url_or_path, target=target_dir)
                clone_args = ["clone"]
                if commit_ref and len(commit_ref) != 40:
                    clone_args.extend(["--branch", commit_ref, "--depth", "1"])
                else:
                    clone_args.extend(["--depth", "50"])
                clone_args.extend([repo_url_or_path, target_dir])

                code, stdout, stderr = _run_git(clone_args, cwd=os.path.dirname(target_dir) or ".")
                if code != 0:
                    # Fallback to plain clone if depth/branch clone fails
                    logger.warning("shallow_clone_fallback", stderr=stderr)
                    _run_git(["clone", repo_url_or_path, target_dir], cwd=os.path.dirname(target_dir) or ".")

        working_path = target_dir if is_remote else repo_url_or_path

        # Checkout commit_ref if specified
        if commit_ref and cls.is_git_repo(working_path):
            _run_git(["checkout", commit_ref], cwd=working_path)

        return cls.get_commit_metadata(working_path)

    @classmethod
    def get_commit_metadata(cls, repo_path: str) -> dict[str, Any]:
        """Extract current commit SHA, author, timestamp, message, and branch."""
        if not cls.is_git_repo(repo_path):
            return {
                "is_git": False,
                "commit_hash": None,
                "author": None,
                "timestamp": None,
                "message": None,
                "branch": None,
            }

        _, commit_hash, _ = _run_git(["rev-parse", "HEAD"], cwd=repo_path)
        _, branch, _ = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_path)
        _, log_line, _ = _run_git(
            ["log", "-1", "--format=%H|%an|%ae|%aI|%s"],
            cwd=repo_path,
        )

        parts = log_line.split("|", 4) if log_line else []
        return {
            "is_git": True,
            "commit_hash": parts[0] if len(parts) > 0 else (commit_hash or None),
            "author": f"{parts[1]} <{parts[2]}>" if len(parts) > 2 else None,
            "timestamp": parts[3] if len(parts) > 3 else None,
            "message": parts[4] if len(parts) > 4 else None,
            "branch": branch or "main",
        }

    @classmethod
    def get_changed_files(
        cls,
        repo_path: str,
        base_commit: str,
        target_commit: str = "HEAD",
    ) -> list[str]:
        """Compute the list of changed files between two commits for incremental scanning."""
        if not cls.is_git_repo(repo_path):
            return []

        code, stdout, _ = _run_git(
            ["diff", "--name-only", f"{base_commit}..{target_commit}"],
            cwd=repo_path,
        )
        if code != 0 or not stdout:
            return []

        return [line.strip() for line in stdout.splitlines() if line.strip()]

    @classmethod
    def scan_crypto_commits(cls, repo_path: str, max_commits: int = 30) -> list[dict[str, Any]]:
        """Inspect recent git commit messages for cryptographic transitions and posture changes."""
        if not cls.is_git_repo(repo_path):
            return []

        code, stdout, _ = _run_git(
            ["log", f"-{max_commits}", "--format=%H|%an|%aI|%s"],
            cwd=repo_path,
        )
        if code != 0 or not stdout:
            return []

        keywords = ("crypto", "tls", "ssl", "rsa", "aes", "sha", "pqc", "cert", "key", "quantum", "fips")
        findings: list[dict[str, Any]] = []

        for line in stdout.splitlines():
            parts = line.strip().split("|", 3)
            if len(parts) < 4:
                continue
            sha, author, dt, msg = parts
            msg_lower = msg.lower()
            matched = [k for k in keywords if k in msg_lower]
            if matched:
                findings.append({
                    "commit_hash": sha,
                    "author": author,
                    "timestamp": dt,
                    "message": msg,
                    "matched_keywords": matched,
                })

        return findings


class GitRepoCollector(CollectorInterface):
    """Collector discovering Git repository metadata and cryptographic history."""

    @property
    def name(self) -> str:
        return "git-repo-collector"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> CollectorCapabilities:
        return CollectorCapabilities(
            languages=["git"],
            ecosystems=["git"],
            asset_types=["protocol", "algorithm"],
            supports_incremental=True,
            requires_network=False,
        )

    async def scan(self, inp: CollectorInput) -> CollectorResult:
        self.validate_input(inp)
        target_path = inp.target_path
        repo_mgr = GitRepositoryManager()

        if not repo_mgr.is_git_repo(target_path):
            return CollectorResult(
                envelopes=[],
                findings_count=0,
                warnings=[f"Target path '{target_path}' is not a valid git repository."],
            )

        meta = repo_mgr.get_commit_metadata(target_path)
        crypto_commits = repo_mgr.scan_crypto_commits(target_path, max_commits=25)

        envelopes: list[EvidenceEnvelope] = []
        collector_info = CollectorInfo(name=self.name, version=self.version)
        run_info = RunInfo(
            scan_id=inp.scan_id,
            collector_run_id=inp.collector_run_id,
            input_revision=meta.get("commit_hash") or inp.input_revision,
        )

        repo_name = Path(target_path).name

        # Emit an envelope for cryptographic commit history if detected
        for item in crypto_commits:
            evidence_str = json.dumps(item, sort_keys=True)
            digest = hashlib.sha256(evidence_str.encode()).hexdigest()

            obs = CryptoObservation(
                observation_type=ObservationType.ALGORITHM_USE,
                algorithm=f"Git-Commit-{item['matched_keywords'][0].upper()}",
                algorithm_raw=item["message"],
                operation="commit_modification",
                usage_evidence=UsageEvidence.STATIC,
                extra={
                    "commit_hash": item["commit_hash"],
                    "author": item["author"],
                    "timestamp": item["timestamp"],
                    "keywords": item["matched_keywords"],
                },
            )

            envelope = EvidenceEnvelope(
                schema_version="1.0",
                collector=collector_info,
                run=run_info,
                tenant_id=inp.tenant_id,
                source_location=SourceLocation(
                    repository=repo_name,
                    path=".git/logs/HEAD",
                    line=1,
                    commit_ref=item["commit_hash"],
                ),
                observation=obs,
                detection_rule=DetectionRule(
                    rule_id="GIT-CRYPTO-COMMIT-001",
                    rule_version="1.0",
                    rule_name="Cryptographic Posture Git Commit",
                ),
                confidence=Confidence.CONFIRMED,
                evidence=EvidenceFingerprint(
                    algorithm="sha256",
                    digest=digest,
                    content_type="application/json",
                    size_bytes=len(evidence_str),
                ),
            )
            envelopes.append(envelope)

        return CollectorResult(
            envelopes=envelopes,
            findings_count=len(envelopes),
        )
