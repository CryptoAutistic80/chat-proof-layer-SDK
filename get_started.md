# Get Started

From the repo root, start with the local SDK and CLI flow.

Generate a stable local signing keypair:

```bash
cargo run -p proofctl -- keygen --out ./keys
```

Create and verify a bundle locally from the included golden fixtures:

```bash
cargo run -p proofctl -- create \
  --input ./fixtures/golden/capture.json \
  --artefact prompt.json=./fixtures/golden/prompt.json \
  --artefact response.json=./fixtures/golden/response.json \
  --key ./keys/signing.pem \
  --out ./bundle.pkg

cargo run -p proofctl -- verify --in ./bundle.pkg --key ./keys/verify.pub
```

If you want the bundle to carry your actor role and system-classification context from day one, create it with the compliance flags instead of adding that data later:

```bash
cargo run -p proofctl -- create \
  --input ./fixtures/golden/capture.json \
  --artefact prompt.json=./fixtures/golden/prompt.json \
  --artefact response.json=./fixtures/golden/response.json \
  --key ./keys/signing.pem \
  --out ./bundle-with-profile.pkg \
  --role deployer \
  --system-id support-assistant \
  --intended-use "Internal reviewer assistance" \
  --prohibited-practice-screening screened_no_prohibited_use \
  --risk-tier limited_risk \
  --gpai-status downstream_integrator \
  --deployment-context internal_operations
```

If you need a deployer-side FRIA track, stamp that into the bundle at creation time so later pack exports can filter on it:

```bash
cargo run -p proofctl -- create \
  --input ./fixtures/golden/capture.json \
  --artefact prompt.json=./fixtures/golden/prompt.json \
  --artefact response.json=./fixtures/golden/response.json \
  --key ./keys/signing.pem \
  --out ./bundle-fria.pkg \
  --role deployer \
  --system-id benefits-review \
  --intended-use "Public-sector eligibility review" \
  --risk-tier high_risk \
  --fria-required true \
  --deployment-context public_sector
```

If you want to use the demo frontend and keep the raw public verify key handy, copy it to your clipboard:

```bash
cat ./keys/verify.pub | xclip -selection clipboard || cat ./keys/verify.pub | wl-copy || cat ./keys/verify.pub | pbcopy
```

If you want the optional self-hosted vault, start it with the matching private signing key:

```bash
export PROOF_SIGNING_KEY_PATH=./keys/signing.pem
cargo run -p proof-service
```

The connected vault exposes the matching public verify key through `/v1/config`, so the demo can verify bundles without a manual paste once it has refreshed.

Once the vault has matching bundles for a system, you can export compliance-oriented packs directly from the CLI:

```bash
# Provider-side governance pack
cargo run -p proofctl -- pack \
  --type provider-governance \
  --vault-url http://127.0.0.1:8080 \
  --system-id system-123 \
  --out ./provider-governance.pack

# Annex IV high-risk governance pack
cargo run -p proofctl -- pack \
  --type annex-iv \
  --vault-url http://127.0.0.1:8080 \
  --system-id hiring-assistant \
  --out ./annex-iv.pack

# Deployer-side FRIA / fundamental rights pack
cargo run -p proofctl -- pack \
  --type fundamental-rights \
  --vault-url http://127.0.0.1:8080 \
  --system-id system-123 \
  --out ./fundamental-rights.pack

# Monitoring / authority-reporting pack
cargo run -p proofctl -- pack \
  --type post-market-monitoring \
  --vault-url http://127.0.0.1:8080 \
  --system-id system-123 \
  --out ./post-market-monitoring.pack
```

If you want end-to-end SDK examples that reuse a default compliance profile and then export the matching pack:

```bash
npm --prefix sdks/typescript build
node examples/typescript-compliance/run.mjs
node examples/typescript-monitoring/run.mjs

python3 packages/sdk-python/scripts/build_native.py
python3 examples/python-annex-iv/run.py
python3 examples/python-compliance/run.py
python3 examples/python-incident-response/run.py
```

In a second terminal, you can start the demo frontend:

```bash
npm --prefix web-demo install
npm --prefix web-demo run dev -- --host 127.0.0.1 --port 5173
```

Then open the local Vite URL shown in the terminal, usually:

```bash
http://127.0.0.1:5173
```

Useful routes once the site is running:

```bash
http://127.0.0.1:5173/
http://127.0.0.1:5173/guided
http://127.0.0.1:5173/playground
http://127.0.0.1:5173/docs
```

`web-demo` is demo-only collateral for walkthroughs and API exercises; it is not the production compliance surface.

If the site is already open, click `Refresh vault` after starting `proof-service` so the verifier and capability panels pick up the current vault state.

If you want both services through Docker instead of two local terminals:

```bash
docker compose up --build
```

That starts:

```bash
proof-service: http://127.0.0.1:8080
web-demo:      http://127.0.0.1:5173
```

The Docker stack uses the checked-in `./vault.toml`, mounts `./keys`, and points the vault at `./keys/signing.pem`, so the public verify key exposed by the API matches `./keys/verify.pub`.

If you want a clean local vault before starting again:

```bash
docker compose down
rm -rf ./storage/artefacts ./storage/backups ./storage/packs ./storage/sled ./storage/metadata.db
mkdir -p ./storage/artefacts ./storage/backups ./storage/packs ./storage/sled
```
