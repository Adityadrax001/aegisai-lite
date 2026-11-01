
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],

  server: {
    port: 5173,

    proxy: {
      "/api/auth": {
        target: "http://127.0.0.1:8081",
        changeOrigin: true,
      },

      "/api/admins": {
        target: "http://127.0.0.1:8081",
        changeOrigin: true,
      },

      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
});
