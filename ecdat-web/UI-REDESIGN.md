# ECDAT workspace update

The graphite sidebar workspace is restored. APK, EXE, and source uploads, results, saved files, and artifact downloads live exclusively on Discovery Scans at http://localhost:3000/scans.

## Capacity and processing

Uploads now allow 500 MB. The frontend reads the API limit; nginx allows 501 MB including multipart overhead and uses 15-minute timeouts. Archives allow 2 GB expanded data, 500 MB per member, and 5,000 entries, with traversal, links, encryption, and duplicate entries rejected. Nested archives are not recursively scanned. Findings are capped at 5,000.

Python and Java files up to 32 MB use existing Tree-sitter collectors. Larger files and other supported inputs use streamed cryptographic indicators. Uploaded programs are never executed; string matches do not establish runtime use.

Originals, metadata, JSON reports, and CSV findings persist under `/evidence_store/uploads/<scan-id>/`. Two scans run concurrently with eight admissions per API process. Unfinished scans become failed on restart; completed artifacts persist.

## Workspace integration

Overview, inventory, policies, advisories, exports, and audit remain available. Inventory reads handle historical mixed-case enum values without rewriting data. Actual Mosca verdicts and QARS scores are displayed. CycloneDX, SARIF, and CSV exports use backend serializers; the placeholder proof verifier was removed.

File-upload reports remain separate from repository inventory and its risk pipeline. This update does not complete the entire ECDAT brief: hardware/cloud discovery, container inspection, runtime verification, and automatic uploaded-file Mosca classification remain outside this change.

The custom mint discovery-frame logo is used in the sidebar and favicon. Design used local redesign-existing-projects, minimalist-ui, and brandkit skills.

## Validation

- 30 backend upload/export tests passed, including streaming boundaries, archive validation, artifact integrity, and restart behavior.
- TypeScript/Vite and Docker frontend builds passed.
- A real 120 MB executable uploaded through nginx, completed scanning, and downloaded with an identical SHA-256 checksum.
- Browser checks passed for scan-only uploader placement, source upload/results, three export formats, desktop and 390px mobile navigation, with no runtime errors.
- Four existing React lint warnings remain in legacy pages; none were introduced in the upload page.
- Verification scans were removed by explicit ID; user uploads were preserved. Screenshots and the browser script are in artifacts/.

Frontend runs on port 3000. Port 80 belongs to another project and was removed from ECDAT compose mappings.


## Git repository integration

Discovery Scans now accepts a public HTTPS GitHub, GitLab or Bitbucket repository and optional branch/tag. A blank ref uses the default branch. The source snapshot and resolved commit are saved with JSON/CSV results. Repository acquisition failure fails the scan explicitly. No repository code executes; submodules, LFS objects and private repositories are not fetched. The bounded acquisition uses Git CLI and the existing source scanning path. A real browser scan, snapshot checksum, mobile layout and failed branch were verified; 35 upload/Git backend tests passed.
