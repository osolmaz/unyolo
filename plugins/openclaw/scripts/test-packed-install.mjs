import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
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
const packageTarball = path.join(temporary, tarball);
const contractTemporary = mkdtempSync(
  path.join(os.tmpdir(), "openclaw-brokerkit-contract-pack-"),
);
writeFileSync(
  path.join(contractTemporary, "package.json"),
  JSON.stringify({ private: true, type: "module" }),
);
run(
  "npm",
  ["install", "--ignore-scripts", "--no-audit", "--no-fund", packageTarball],
  contractTemporary,
);
run(
  process.execPath,
  [
    "--input-type=module",
    "--eval",
    [
      'const contract = await import("openclaw-brokerkit/operator-v1");',
      'if (contract.operatorV1.apiVersion !== "brokerkit.io/operator/v1") throw new Error("contract metadata missing");',
      'const request = {id:"request-1",revision:1,requester:"bob",operation:"repo.read",status:"pending",requested_at:"2026-07-19T00:00:00Z",requested_duration_seconds:300,requested_max_uses:1,granted_max_uses:null,used_count:0,presentation:{risk:"low",title:"Read repository",target:"example/project",warnings:[],plan_hash:"sha256:test"},allowed_actions:["approve","deny"]};',
      'if (contract.parseRequest(request).presentation.target !== "example/project") throw new Error("contract parser rejected canonical request");',
      'try { contract.parseRequest({...request, revision: Number.MAX_SAFE_INTEGER + 1}); throw new Error("unsafe integer accepted"); } catch (error) { if (error.message === "unsafe integer accepted") throw error; }',
    ].join(" "),
  ],
  contractTemporary,
);
if (existsSync(path.join(contractTemporary, "node_modules", "openclaw")))
  throw new Error("contract-only install pulled in the optional OpenClaw host");
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
    "openclaw@2026.7.1",
    packageTarball,
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
if (installed.peerDependencies?.openclaw !== ">=2026.7.1")
  throw new Error(
    "packed plugin has an unexpected OpenClaw compatibility range",
  );
if (installed.peerDependenciesMeta?.openclaw?.optional !== true)
  throw new Error(
    "packed contract consumer must not install the OpenClaw host",
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
  !/<script defer src="\/plugins\/brokerkit\/ui\/assets\/index-[^"]+\.js"><\/script>/u.test(
    uiIndex,
  )
)
  throw new Error("packed UI is missing its classic sandbox entrypoint");
if (uiIndex.includes("crossorigin"))
  throw new Error("packed UI assets must not require CORS mode");

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
