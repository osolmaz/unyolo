import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { pluginSkills } from "./skill-layout.mjs";

const packageDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const outputRoot = path.join(packageDir, "dist", "skills");

rmSync(outputRoot, { force: true, recursive: true });
mkdirSync(outputRoot, { recursive: true });

for (const skill of pluginSkills) {
  const source = path.resolve(packageDir, skill.source);
  if (!existsSync(path.join(source, "SKILL.md"))) {
    throw new Error(`BrokerKit skill ${skill.name} is missing SKILL.md`);
  }
  cpSync(source, path.join(outputRoot, skill.name), { recursive: true });
}
