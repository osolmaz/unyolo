import { readFile, writeFile } from "node:fs/promises";
import process from "node:process";
import { fileURLToPath, URL } from "node:url";

import {
  isSensitiveFieldKey,
  redactSensitiveFieldValue,
} from "openclaw/plugin-sdk/text-runtime";

const packageDocument = JSON.parse(
  await readFile(
    new URL("../node_modules/openclaw/package.json", import.meta.url),
    "utf8",
  ),
);
const expectedVersion = "2026.7.1";
if (packageDocument.version !== expectedVersion) {
  throw new Error(
    `OpenClaw fixture requires ${expectedVersion}, got ${packageDocument.version}`,
  );
}

const names = [
  "access_token",
  "api_key",
  "api_token",
  "armored_public_key",
  "armored_public_material",
  "authorization",
  "cache_identifier",
  "card_number",
  "client_secret",
  "commit_signature",
  "cookie",
  "credential",
  "deploy_key",
  "document_name",
  "hide_secret",
  "hide_sensitive_value",
  "idempotency_key",
  "key",
  "object_path",
  "operation_id",
  "password",
  "private_key",
  "public_material",
  "refresh_token",
  "request_id",
  "request_key",
  "secret",
  "secret_name",
  "session",
  "signature",
  "token",
  "transfer_id",
  "variable_name",
];

const fixture = {
  source: {
    package: "openclaw",
    version: expectedVersion,
    integrity:
      "sha512-ge/Xss99CHAjPL/ikmH/UFoiOrjcxDB4sW3y9mhyCD+dYW3wzV7TKbAVdkrXFgAG2d2BjpJofP97zUZ+umxo8g==",
    entrypoint: "openclaw/plugin-sdk/text-runtime",
  },
  cases: names.map((name) => ({
    name,
    sensitive: isSensitiveFieldKey(name),
    short_value: redactSensitiveFieldValue(name, "hunter2"),
    long_value: redactSensitiveFieldValue(name, "abcdefghijklmnopqrstu"),
  })),
};
const output = `${JSON.stringify(fixture, null, 2)}\n`;
const target = new URL(
  "../../../capability/testdata/openclaw-redaction-v2026.7.1.json",
  import.meta.url,
);

if (process.argv.includes("--check")) {
  const current = await readFile(target, "utf8");
  if (current !== output) {
    throw new Error(
      `${fileURLToPath(target)} is stale; run pnpm generate:redaction-fixture`,
    );
  }
} else {
  await writeFile(target, output);
}
