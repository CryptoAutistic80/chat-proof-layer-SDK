# Release and Operations Guide (Dual-SDK v1)

This document defines release metadata, versioning, signing, migration, onboarding, and operations workflows for the Proof Layer SDK fork with **Python + TypeScript** as first-class v1 deliverables.

## 1) Package metadata and versioning strategy

## Python package (PyPI)

- **Canonical distribution name:** `proof-layer-sdk-python`
- **Import path:** `proofsdk`
- **Current metadata source:** `packages/sdk-python/pyproject.toml`

## TypeScript package (npm)

- **Canonical package name:** `@proof-layer/sdk`
- **Entrypoint + exports:** `sdks/typescript/package.json`
- **Current metadata source:** `sdks/typescript/package.json`

## Versioning policy (shared)

Use **SemVer** (`MAJOR.MINOR.PATCH`) with SDK release tags in the form `sdk-vX.Y.Z`.

Compatibility rules:

- **MAJOR:** breaking API/schema/CLI behavior change
- **MINOR:** backward-compatible features, new optional fields, additive CLI options
- **PATCH:** bug fixes, security patches, internal hardening without API breaks

Evidence bundle/schema compatibility:

- Bundles include `schema_version`.
- Verifier supports current major and one previous minor schema version at minimum.
- Any incompatible schema change requires a major release and migration notes.

## 2) Signed release/tag process and changelog policy

## Signed tags and releases

1. Prepare release branch (`release/vX.Y`).
2. Run required checks (Python + TypeScript + schema + packaging).
3. Update version and changelog.
4. Create **annotated signed tag**: `git tag -s sdk-vX.Y.Z -m "SDK release vX.Y.Z"`
5. Push branch + tag.
6. CI builds release artifacts and publishes where credentials are configured.

## Publish channels

- **PyPI:** publish wheel artifacts when `PYPI_API_TOKEN` is configured.
- **npm:** publish package when npm token is configured and release approvals pass.

## Changelog policy

Maintain `CHANGELOG.md` using **Keep a Changelog** categories:

- Added
- Changed
- Deprecated
- Removed
- Fixed
- Security

Rules:

- Every PR includes a changelog fragment unless marked `no-changelog`.
- Security fixes are explicitly tagged and reference advisory IDs.
- Migration-impacting entries include a “Required action” note.
- Release notes link to signed tag and verification instructions.

## 3) Migration guide: broad monorepo surface -> release-critical dual SDK

## Objective

Keep broad repository development surfaces, but make release-critical paths strictly centered on Python + TypeScript SDKs and shared schema/verification contracts.

## Migration checklist

1. **Inventory current usage**
   - Identify all imports of Python/TypeScript SDK APIs in downstream integrations.
2. **Freeze dependency graph**
   - Pin source commit and export SBOM/dependency list for audit baseline.
3. **Align API semantics**
   - Use common lifecycle (`start`, `log_user/logUser`, `log_ai/logAI`, `finish`) across both SDKs.
4. **Align data artifacts**
   - Standardize evidence bundle structure and metadata fields.
   - Enforce `schema_version` and signature validation in CI.
5. **Rewire CI/CD**
   - Keep release blockers green for Python + TypeScript + schema checks.
6. **Cutover and rollback plan**
   - Run dual validation cycle in staging and define rollback triggers.

## Definition of done for migration

- Production chat flows can use either Python or TypeScript SDK with compatible bundle verification.
- Verification success rate for generated bundles meets SLO target.
- Release gates cover both SDK packages and shared schema validation.
- Runbooks and on-call docs updated.

## 4) Getting started in 15 minutes

## Prerequisites (2 minutes)

- Python 3.10+
- Node 20+
- A signing keypair (generated locally for dev)

## Python quickstart (6 minutes)

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install proof-layer-sdk-python
```

```python
from proofsdk import ProofLayer

proof = ProofLayer.load(private_key_path="./keys/signing_private.pem")
session = proof.start_chat_session(provider="openai", model="gpt-4.1-mini")
session.log_user("Summarize EU AI Act Article 12 obligations.")
session.log_ai("Article 12 centers on logging and traceability obligations.")
result = session.finish_session()
```

## TypeScript quickstart (6 minutes)

```bash
cd sdks/typescript
npm ci
npm run build
```

```ts
import { ProofLayer } from "@proof-layer/sdk";

const proof = ProofLayer.load({ signingKeyPath: "./keys/signing_private.pem" });
const session = proof.startChatSession({ provider: "openai", model: "gpt-4.1-mini" });
session.logUser("Summarize EU AI Act Article 12 obligations.");
session.logAI("Article 12 centers on logging and traceability obligations.");
const result = await session.finishSession();
```

## 5) Ops runbook: key rotation, incident retrieval, verification workflows

## A. Key rotation runbook

1. Generate new keypair in KMS/HSM or approved secure environment.
2. Register new public key with `key_id` and `valid_from` timestamp.
3. Deploy signer update with dual-trust overlap window.
4. Revoke old key at cutoff and record rotation evidence.

## B. Incident retrieval runbook

1. Gather identifiers (session ID, tenant ID, time window, incident ticket).
2. Retrieve evidence bundle(s) and associated signing metadata.
3. Verify signatures and chain-of-custody metadata.
4. Export incident package (bundle + verifier output + key provenance + audit trail).

## C. Verification workflow runbook

Manual template:

```bash
proofsdk verify --bundle <bundle_path> --public-key <public_key_path> --verbose
```

Decision matrix:

- `valid`: archive result and continue.
- `invalid_signature`: open security incident and quarantine artifacts.
- `schema_mismatch`: evaluate compatibility policy breach.
- `missing_key`: recover trust-store entry from key registry backup.
