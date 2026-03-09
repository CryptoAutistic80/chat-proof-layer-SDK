import { defineConfig } from "vite";

export default defineConfig({
  server: {
    host: true,
    port: 5173
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{js,jsx}"],
    exclude: ["tests/**", "node_modules/**"]
  }
});
