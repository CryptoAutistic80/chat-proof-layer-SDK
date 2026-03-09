import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  use: {
    baseURL: "http://127.0.0.1:5173",
    headless: true
  },
  webServer: [
    {
      command: "cargo run -p proof-service --manifest-path ../Cargo.toml",
      url: "http://127.0.0.1:8080/healthz",
      reuseExistingServer: true,
      timeout: 120_000
    },
    {
      command: "npm run dev -- --host 127.0.0.1 --port 5173",
      url: "http://127.0.0.1:5173/playground",
      reuseExistingServer: true,
      timeout: 120_000
    }
  ]
});
