import { defineConfig } from "vite";

const forwardedHosts = (process.env.WEB_DEMO_ALLOWED_HOSTS ?? "")
  .split(",")
  .map((host) => host.trim())
  .filter(Boolean);

export default defineConfig({
  server: {
    host: true,
    port: 5173,
    allowedHosts: [
      "uncentrical-scrawnily-sima.ngrok-free.dev",
      ".ngrok-free.dev",
      ...forwardedHosts
    ]
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{js,jsx}"],
    exclude: ["tests/**", "node_modules/**"]
  }
});
