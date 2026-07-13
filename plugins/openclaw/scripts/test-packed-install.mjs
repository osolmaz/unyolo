import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const temporary = mkdtempSync(
  path.join(os.tmpdir(), "openclaw-brokerkit-pack-"),
);
run("npm", ["pack", "--pack-destination", temporary], packageDir);
const tarball = readdirSync(temporary).find((file) => file.endsWith(".tgz"));
if (!tarball) throw new Error("npm pack did not produce a tarball");
writeFileSync(
  path.join(temporary, "package.json"),
  JSON.stringify({ private: true, type: "module" }),
);
run(
  "npm",
  [
    "install",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "openclaw@2026.7.1-beta.5",
    path.join(temporary, tarball),
  ],
  temporary,
);
run(
  process.execPath,
  [
    "--input-type=module",
    "--eval",
    'const plugin = await import("openclaw-brokerkit"); if (!plugin.default) throw new Error("plugin entry missing");',
  ],
  temporary,
);
const installed = JSON.parse(
  readFileSync(
    path.join(temporary, "node_modules", "openclaw-brokerkit", "package.json"),
    "utf8",
  ),
);
if (installed.peerDependencies?.openclaw !== ">=2026.7.1-beta.5")
  throw new Error(
    "packed plugin has an unexpected OpenClaw compatibility range",
  );
const installedRoot = path.join(
  temporary,
  "node_modules",
  "openclaw-brokerkit",
);
const uiIndex = readFileSync(
  path.join(installedRoot, "dist", "ui", "index.html"),
  "utf8",
);
if (uiIndex.includes('type="module"'))
  throw new Error("packed UI must not require a module entrypoint");
if (
  !/<script defer crossorigin src="\/plugins\/brokerkit\/ui\/assets\/index-[^"]+\.js"><\/script>/u.test(
    uiIndex,
  )
)
  throw new Error("packed UI is missing its classic sandbox entrypoint");

function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  });
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    throw new Error(`${command} failed with status ${result.status}`);
  }
}
