# Get Started

From the repo root, generate a stable local signing keypair and copy the matching public verify key to your clipboard for the frontend demo:

```bash
cargo run -p proofctl -- keygen --out ./keys && cat ./keys/verify.pub | xclip -selection clipboard
```

If `xclip` is not available, use this fallback instead:

```bash
cargo run -p proofctl -- keygen --out ./keys && (cat ./keys/verify.pub | xclip -selection clipboard || cat ./keys/verify.pub | wl-copy || cat ./keys/verify.pub | pbcopy)
```

Start the vault with the matching private signing key:

```bash
export PROOF_SIGNING_KEY_PATH=./keys/signing.pem
cargo run -p proof-service
```

In a second terminal, start the web demo:

```bash
cd web-demo
npm install
npm run dev
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

If the site is already open, click `Refresh vault` after starting `proof-service` so the verifier and capability panels pick up the current vault state.
