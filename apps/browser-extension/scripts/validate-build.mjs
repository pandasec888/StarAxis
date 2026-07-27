import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const targets = ["chrome", "edge", "firefox"];
const exactPermissions = [
  "activeTab",
  "nativeMessaging",
  "scripting",
  "storage",
];
const forbiddenPermissions = new Set([
  "<all_urls>",
  "clipboardRead",
  "clipboardWrite",
  "cookies",
  "debugger",
  "history",
  "webRequest",
]);

for (const target of targets) {
  const directory = path.join(root, "dist", target);
  const manifestPath = path.join(directory, "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  assert(manifest.manifest_version === 3, `${target}: Manifest V3 required`);
  assert(
    !manifest.host_permissions,
    `${target}: host_permissions must stay implicit in the reviewed web content script`,
  );
  assert(
    manifest.content_scripts?.length === 1 &&
      JSON.stringify(manifest.content_scripts[0].matches) ===
        JSON.stringify(["http://*/*", "https://*/*"]) &&
      manifest.content_scripts[0].js?.[0] === "assets/content.js" &&
      manifest.content_scripts[0].run_at === "document_start" &&
      manifest.content_scripts[0].all_frames === false,
    `${target}: reviewed top-level HTTP/HTTPS capture script configuration changed`,
  );
  assert(
    JSON.stringify([...manifest.permissions].sort()) ===
      JSON.stringify(exactPermissions),
    `${target}: permission baseline changed`,
  );
  assert(
    !manifest.permissions.some((permission) =>
      forbiddenPermissions.has(permission),
    ),
    `${target}: forbidden permission present`,
  );
  if (target === "firefox") {
    assert(
      manifest.background?.scripts?.[0] === "assets/background.js" &&
        manifest.background?.type === "module",
      "firefox: event-page module background required",
    );
    assert(
      manifest.browser_specific_settings?.gecko?.id ===
        "browser@staraxis.local",
      "firefox: stable Gecko ID required",
    );
  } else {
    assert(
      manifest.background?.service_worker === "assets/background.js" &&
        manifest.background?.type === "module",
      `${target}: module service worker required`,
    );
  }
  for (const required of [
    "popup.html",
    "assets/background.js",
    "assets/content.js",
    "icons/32x32.png",
    "icons/128x128.png",
  ]) {
    assert(
      fs.statSync(path.join(directory, required)).isFile(),
      `${target}: missing ${required}`,
    );
  }
  for (const file of walk(directory)) {
    assert(!file.endsWith(".map"), `${target}: source map included`);
    assert(
      !/\.(test|spec)\.[cm]?[jt]sx?$/u.test(file),
      `${target}: test file included`,
    );
    if (file.endsWith(".js")) {
      const source = fs.readFileSync(file, "utf8");
      if (file.endsWith(path.join("assets", "content.js"))) {
        assert(
          !/^\s*import\s/mu.test(source),
          `${target}: classic content script must be self-contained`,
        );
      }
      assert(
        !/\b(?:eval|Function)\s*\(/u.test(source),
        `${target}: dynamic code execution found`,
      );
      assert(
        !source.includes("sourceMappingURL"),
        `${target}: source map reference found`,
      );
    }
  }
}

assert(
  !fs.existsSync(path.join(root, "dist", "safari")),
  "Safari artifact must remain absent",
);

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(file) : [file];
  });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
