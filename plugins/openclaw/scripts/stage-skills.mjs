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
  const document = path.join(source, "SKILL.md");
  if (!existsSync(document)) {
    throw new Error(`unYOLO skill ${skill.name} is missing SKILL.md`);
  }
  // Copy only SKILL.md: the skill source directory also holds the Go embed
  // file that bundles the same document into the broker binary.
  const target = path.join(outputRoot, skill.name);
  mkdirSync(target, { recursive: true });
  cpSync(document, path.join(target, "SKILL.md"));
}
