import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    ...(process.env.VIZIER_UI_CHECK === "1" ? { hmr: false } : {}),
    proxy: {
      "/api": "http://127.0.0.1:4300",
      "/health": "http://127.0.0.1:4300",
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test-setup.ts",
    css: true,
  },
});
