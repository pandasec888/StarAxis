import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const HOST_NAME = "com.staraxis.browser";
const args = new Map();
for (let index = 2; index < process.argv.length;) {
  const option = process.argv[index];
  if (option === "--remove") {
    args.set(option, "true");
    index += 1;
    continue;
  }
  const value = process.argv[index + 1];
  if (!option?.startsWith("--") || value === undefined) {
    throw new Error(`Invalid installer argument: ${option ?? "<missing>"}`);
  }
  args.set(option, value);
  index += 2;
}

const remove = args.has("--remove");
const homeDirectory = path.resolve(args.get("--home") ?? os.homedir());
const hostPath = path.resolve(
  args.get("--host") ??
    path.join(
      "target",
      "release",
      process.platform === "win32"
        ? "vault-extension-host.exe"
        : "vault-extension-host",
    ),
);
const chromeId = args.get("--chrome-id");
const edgeId = args.get("--edge-id");
const firefoxId = args.get("--firefox-id") ?? "browser@staraxis.local";

if (!remove && !fs.existsSync(hostPath)) {
  throw new Error(`Native Messaging host does not exist: ${hostPath}`);
}

const chromiumManifest = (origins) => ({
  name: HOST_NAME,
  description: "StarAxis secure browser bridge",
  path: hostPath,
  type: "stdio",
  allowed_origins: origins.map((id) => `chrome-extension://${id}/`),
});
const firefoxManifest = {
  name: HOST_NAME,
  description: "StarAxis secure browser bridge",
  path: hostPath,
  type: "stdio",
  allowed_extensions: [firefoxId],
};

if (process.platform === "darwin") {
  installFile(
    path.join(
      homeDirectory,
      "Library/Application Support/Google/Chrome/NativeMessagingHosts",
      `${HOST_NAME}.json`,
    ),
    chromiumManifest(requiredIds(chromeId, "--chrome-id")),
  );
  installFile(
    path.join(
      homeDirectory,
      "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
      `${HOST_NAME}.json`,
    ),
    chromiumManifest(requiredIds(edgeId, "--edge-id")),
  );
  installFile(
    path.join(
      homeDirectory,
      "Library/Application Support/Mozilla/NativeMessagingHosts",
      `${HOST_NAME}.json`,
    ),
    firefoxManifest,
  );
} else if (process.platform === "linux") {
  installFile(
    path.join(
      homeDirectory,
      ".config/google-chrome/NativeMessagingHosts",
      `${HOST_NAME}.json`,
    ),
    chromiumManifest(requiredIds(chromeId, "--chrome-id")),
  );
  installFile(
    path.join(
      homeDirectory,
      ".config/microsoft-edge/NativeMessagingHosts",
      `${HOST_NAME}.json`,
    ),
    chromiumManifest(requiredIds(edgeId, "--edge-id")),
  );
  installFile(
    path.join(
      homeDirectory,
      ".mozilla/native-messaging-hosts",
      `${HOST_NAME}.json`,
    ),
    firefoxManifest,
  );
} else if (process.platform === "win32") {
  const manifestDirectory = path.join(
    args.get("--home") ?? process.env.LOCALAPPDATA ?? os.homedir(),
    "StarAxis",
    "NativeMessagingHosts",
  );
  const chromiumPath = path.join(
    manifestDirectory,
    `${HOST_NAME}.chromium.json`,
  );
  const firefoxPath = path.join(manifestDirectory, `${HOST_NAME}.firefox.json`);
  installFile(
    chromiumPath,
    chromiumManifest([
      ...requiredIds(chromeId, "--chrome-id"),
      ...requiredIds(edgeId, "--edge-id"),
    ]),
  );
  installFile(firefoxPath, firefoxManifest);
  registry(
    "HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts",
    chromiumPath,
  );
  registry(
    "HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts",
    chromiumPath,
  );
  registry("HKCU\\Software\\Mozilla\\NativeMessagingHosts", firefoxPath);
} else {
  throw new Error(`Unsupported platform: ${process.platform}`);
}

function requiredIds(value, option) {
  if (remove) return [];
  if (!value || !/^[a-z]{32}$/u.test(value)) {
    throw new Error(
      `${option} must be the 32-letter extension ID shown by the browser`,
    );
  }
  return [value];
}

function installFile(file, content) {
  if (remove) {
    fs.rmSync(file, { force: true });
    return;
  }
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, `${JSON.stringify(content, null, 2)}\n`, {
    mode: 0o600,
  });
  fs.renameSync(temporary, file);
}

function registry(base, manifestPath) {
  const key = `${base}\\${HOST_NAME}`;
  if (remove) {
    try {
      execFileSync("reg.exe", ["delete", key, "/f"], { stdio: "ignore" });
    } catch {
      // An already-absent per-user registration is a successful uninstall.
    }
  } else {
    execFileSync(
      "reg.exe",
      ["add", key, "/ve", "/t", "REG_SZ", "/d", manifestPath, "/f"],
      {
        stdio: "ignore",
      },
    );
  }
}
