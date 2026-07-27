import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const root = path.dirname(fileURLToPath(import.meta.url));

type BrowserTarget = "chrome" | "edge" | "firefox";

function manifestFor(target: BrowserTarget) {
  const common = {
    manifest_version: 3,
    name: "StarAxis — Secure Fill",
    short_name: "StarAxis",
    description:
      "Securely fill credentials through the local StarAxis desktop app and offer to save or update them after sign-in.",
    version: "1.0.0",
    permissions: ["activeTab", "scripting", "nativeMessaging", "storage"],
    action: {
      default_title: "StarAxis",
      default_popup: "popup.html",
    },
    icons: {
      "32": "icons/32x32.png",
      "128": "icons/128x128.png",
    },
    content_security_policy: {
      extension_pages: "script-src 'self'; object-src 'none'; base-uri 'none'",
    },
    content_scripts: [
      {
        matches: ["http://*/*", "https://*/*"],
        js: ["assets/content.js"],
        run_at: "document_start",
        all_frames: false,
      },
    ],
  };
  if (target === "firefox") {
    return {
      ...common,
      background: { scripts: ["assets/background.js"], type: "module" },
      browser_specific_settings: {
        gecko: {
          id: "browser@staraxis.local",
          strict_min_version: "128.0",
          data_collection_permissions: { required: ["none"] },
        },
      },
    };
  }
  return {
    ...common,
    background: { service_worker: "assets/background.js", type: "module" },
  };
}

export default defineConfig(({ mode }) => {
  const target: BrowserTarget =
    mode === "edge" || mode === "firefox" ? mode : "chrome";
  const outDir = path.resolve(root, "dist", target);
  return {
    plugins: [
      react(),
      {
        name: "staraxis-extension-manifest",
        closeBundle() {
          fs.mkdirSync(path.join(outDir, "icons"), { recursive: true });
          fs.writeFileSync(
            path.join(outDir, "manifest.json"),
            `${JSON.stringify(manifestFor(target), null, 2)}\n`,
          );
          for (const file of ["32x32.png", "128x128.png"]) {
            fs.copyFileSync(
              path.resolve(root, "../desktop/src-tauri/icons", file),
              path.join(outDir, "icons", file),
            );
          }
        },
      },
    ],
    build: {
      outDir,
      emptyOutDir: true,
      assetsInlineLimit: 0,
      rollupOptions: {
        input: {
          popup: path.resolve(root, "popup.html"),
          background: path.resolve(root, "src/background.ts"),
          content: path.resolve(root, "src/content.ts"),
        },
        output: {
          entryFileNames: "assets/[name].js",
          chunkFileNames: "assets/[name]-[hash].js",
          assetFileNames: "assets/[name]-[hash][extname]",
        },
      },
    },
    test: {
      environment: "jsdom",
      environmentOptions: {
        jsdom: { url: "https://example.com/login" },
      },
    },
  };
});
