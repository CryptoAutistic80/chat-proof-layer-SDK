# Release and Operations Guide (Minimal Fork)

This document defines release metadata, versioning, signing, migration, onboarding, and operations workflows for the minimal Python-first Proof Layer SDK fork.

## 1) Package metadata and versioning strategy

## Python package (PyPI)

**Canonical package name:** `proof-layer-sdk` (distribution)<br>
**Import path:** `proofsdk` (module)

Recommended metadata fields for `pyproject.toml`:

- `name = "proof-layer-sdk"`
- `description = "Tamper-evident chat transcript proof logging and verification SDK"`
- `license` and SPDX identifier
- `authors` and `maintainers`
- `readme = "README.md"`
- `requires-python = ">=3.10"`
- `classifiers`:
  - Production/Stable status when GA
  - Security and cryptography topic tags
  - Python versions tested in CI
- `project.urls`:
  - Documentation
  - Source repository
  - Changelog
  - Security policy

### npm metadata policy (status)

- **v1 policy:** no npm package is published.
- Reserve `@proof-layer/sdk` for post-v1 TypeScript parity to avoid namespace squat.
- If/when npm is introduced, align metadata fields with PyPI (description, docs, changelog, security contact, license).

### Versioning policy

Use **SemVer** (`MAJOR.MINOR.PATCH`) with release channels:

- `v1.0.0` for first stable GA
- `v1.x.y` for stable releases
- `v1.1.0-rc.1` for release candidates
- `v1.2.0b1` allowed only for pre-GA beta channel (if needed)

Compatibility rules:

- **MAJOR:** breaking API/schema/CLI behavior change
- **MINOR:** backward-compatible features, new optional fields, additive CLI options
- **PATCH:** bug fixes, security patches, internal hardening without API breaks

Evidence bundle/schema compatibility:

- Bundle schema must include `schema_version`.
- Verifier must support current major and one previous minor schema version at minimum.
- Any incompatible schema change requires a major release and migration notes.

## 2) Signed release/tag process and changelog policy

## Signed tags and releases

1. Prepare release branch (`release/vX.Y`).
2. Run required checks: lint, unit, integration, verification, packaging dry-run.
3. Update version and changelog.
4. Create **annotated signed tag**:
   - `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
5. Push branch + tag.
6. CI verifies tag signature, builds artifacts, and publishes to PyPI.
7. Generate GitHub/GitLab release notes from changelog sections.

Signing standards:

- Use organization-managed signing keys (GPG or Sigstore keyless workflow).
- Rotate maintainer signing keys at least annually or on role changes.
- Keep public keys discoverable in docs/security policy.

## Changelog policy

Maintain `CHANGELOG.md` using **Keep a Changelog** categories:

- Added
- Changed
- Deprecated
- Removed
- Fixed
- Security

Rules:

- Every PR must include a changelog fragment unless marked `no-changelog`.
- Security fixes are explicitly tagged and reference advisory IDs.
- Migration-impacting entries must include a “Required action” note.
- Release notes link to signed tag and verification instructions.

## 3) Migration guide: broad monorepo surface -> minimal fork

## Objective

Move from a multi-language monorepo workflow to a Python-first minimal fork with stricter compliance and release boundaries.

## Migration checklist

1. **Inventory current usage**
   - Identify all imports of TypeScript SDK, Rust wrappers, demos, and helper scripts.
   - Map used APIs to minimal Python API equivalents.
2. **Freeze dependency graph**
   - Pin source commit and export SBOM/dependency list for audit baseline.
3. **Port integration paths**
   - Replace broad surface calls with:
     - `start_session`
     - `log_user`
     - `log_ai`
     - `finish_session`
     - `verify_bundle`
4. **Remove non-minimal surfaces**
   - Decommission demo/UI dependencies from production paths.
   - Archive TS-specific adapters behind post-v1 backlog.
5. **Align data artifacts**
   - Standardize evidence bundle structure and metadata fields.
   - Enforce `schema_version` and signature validation in CI.
6. **Rewire CI/CD**
   - Keep only Python package build/test/release jobs.
   - Add signed-tag verification gate.
7. **Cutover and rollback plan**
   - Run dual-write (old/new logs) for at least one staging cycle.
   - Define rollback trigger thresholds (verification failures, latency regressions).

## Definition of done for migration

- All production chat flows use minimal Python SDK APIs.
- Verification success rate for generated bundles meets SLO target.
- Legacy monorepo surfaces are removed from release-critical paths.
- Runbooks and on-call docs updated.

## 4) Getting started in 15 minutes

## Prerequisites (2 minutes)

- Python 3.10+
- Virtual environment tooling (`venv` or `uv`)
- A signing keypair (generated locally for dev)

## Install (3 minutes)

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install proof-layer-sdk
```

## Generate dev keys (2 minutes)

```bash
proofsdk keys generate --out-dir ./keys
```

Expected outputs:

- `keys/signing_private.pem` (keep secret)
- `keys/signing_public.pem` (share for verification)

## Add SDK to a chat flow (5 minutes)

```python
from proofsdk import ProofLayer

proof = ProofLayer.load(private_key_path="./keys/signing_private.pem")
proof.start_session(session_id="demo-session-001")

user_prompt = "Summarize the key obligations under EU AI Act Article 12."
proof.log_user(user_prompt)

assistant_response = "Article 12 emphasizes logging and traceability obligations..."
proof.log_ai(assistant_response)

bundle = proof.finish_session()
with open("./artifacts/demo_bundle.json", "w", encoding="utf-8") as f:
    f.write(bundle.model_dump_json(indent=2))
```

## Verify a bundle (3 minutes)

```bash
proofsdk verify \
  --bundle ./artifacts/demo_bundle.json \
  --public-key ./keys/signing_public.pem
```

Exit criteria for successful quickstart:

- Bundle file generated
- Verification command exits zero
- Tamper test (edit one message) causes verification failure

## 5) Ops runbook: key rotation, incident retrieval, verification workflows

## A. Key rotation runbook

**Trigger events**

- Scheduled rotation (e.g., every 90 days for service keys)
- Personnel change or role revocation
- Suspected key exposure

**Procedure**

1. Generate new keypair in KMS/HSM or approved secure environment.
2. Register new public key with `key_id` and `valid_from` timestamp.
3. Deploy signer update using dual-publish window:
   - new sessions signed with new key
   - verifiers trust both old+new keys temporarily
4. Backfill config in all environments (dev/stage/prod).
5. Revoke old key at cutoff timestamp.
6. Record rotation event in security log and changelog/security notes.

**Post-rotation checks**

- Verify new bundles validate with new key.
- Verify historical bundles still validate with retained trust set.
- Confirm revoked key no longer accepted for new timestamps.

## B. Incident retrieval runbook

**Use cases**

- Regulatory inquiry
- Customer dispute
- Internal safety/security incident review

**Procedure**

1. Gather identifiers (session ID, tenant ID, time window, incident ticket).
2. Retrieve evidence bundle(s) and associated signing metadata.
3. Hash and checksum retrieved artifacts on ingest.
4. Verify signatures and chain-of-custody metadata.
5. Export incident package:
   - raw bundle
   - verification output
   - key provenance
   - retrieval audit record
6. Store immutable copy in incident evidence vault.

**SLO target**

- P1 retrieval and verification package assembled within 60 minutes.

## C. Verification workflow runbook

**Continuous verification (CI + runtime)**

- CI validates sample bundles on every release candidate.
- Production can run asynchronous verifier sweeps for integrity drift detection.

**Manual verification command template**

```bash
proofsdk verify \
  --bundle <bundle_path> \
  --public-key <public_key_path> \
  --verbose
```

**Decision matrix**

- `valid`: archive result and continue.
- `invalid_signature`: open security incident; quarantine affected artifacts.
- `schema_mismatch`: route to platform team; evaluate compatibility policy breach.
- `missing_key`: restore trust-store entry or recover from key registry backup.

## Operational records (required)

- Key registry with lifecycle timestamps
- Rotation log and approvals
- Verification run logs
- Incident retrieval audit trails
- Release provenance records (signed tags + build attestations)
