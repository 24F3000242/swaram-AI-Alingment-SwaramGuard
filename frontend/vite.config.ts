import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // ws: true so the live stream (WebSocket /api/live) goes through the dev proxy too.
    proxy: { "/api": { target: process.env.SWARMGUARD_API ?? "http://127.0.0.1:8000", ws: true } },
  },
  test: { environment: "node" },
} as never);
