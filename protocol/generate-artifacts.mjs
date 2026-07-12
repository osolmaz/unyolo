import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { format } from "prettier";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const check = process.argv.includes("--check");
const specs = [
  {
    name: "operator",
    input: "protocol/openapi/operator-v1.yaml",
    outputDir: "protocol/schema",
    schemas: {
      Decision: "decision.schema.json",
      Descriptor: "discovery.schema.json",
      ErrorEnvelope: "error.schema.json",
      BrokerEvent: "event.schema.json",
      RequestPage: "page.schema.json",
      Presentation: "presentation.schema.json",
      BrokerRequest: "request.schema.json",
    },
    idBase: "https://brokerkit.dev/schema/operator/v1/",
  },
  {
    name: "agent",
    input: "protocol/openapi/agent-v1.yaml",
    outputDir: "protocol/agent-schema",
    schemas: {
      Descriptor: "discovery.schema.json",
      ErrorEnvelope: "error.schema.json",
      Operation: "operation.schema.json",
      SubmitRequest: "submit.schema.json",
    },
    idBase: "https://brokerkit.io/schema/agent/v1/",
  },
];

let stale = false;
for (const spec of specs) {
  const inputPath = path.join(root, spec.input);
  const source = readFileSync(inputPath, "utf8");
  const document = JSON.parse(source);
  const components = document.components?.schemas;
  if (!components || typeof components !== "object")
    throw new Error(`${spec.input} has no component schemas`);
  for (const [schemaName, filename] of Object.entries(spec.schemas)) {
    if (!components[schemaName])
      throw new Error(`${spec.input} has no ${schemaName} schema`);
    const artifact = {
      $comment: `Generated from ${spec.input}; do not edit.`,
      $schema: "https://json-schema.org/draft/2020-12/schema",
      $id: spec.idBase + filename,
      ...rewriteRefs(structuredClone(components[schemaName])),
      $defs: rewriteRefs(structuredClone(components)),
    };
    emit(
      path.join(root, spec.outputDir, filename),
      `${JSON.stringify(artifact, null, 2)}\n`,
    );
  }
  if (spec.name === "operator") {
    await emitOperatorWrapper(source, components);
    await emitOperatorSchemas(components);
  }
}
if (stale) process.exit(1);

function rewriteRefs(value) {
  if (Array.isArray(value)) return value.map(rewriteRefs);
  if (!value || typeof value !== "object") return value;
  for (const [key, child] of Object.entries(value)) {
    if (key === "$ref" && typeof child === "string") {
      value[key] = child.replace("#/components/schemas/", "#/$defs/");
    } else {
      value[key] = rewriteRefs(child);
    }
  }
  return value;
}

async function emitOperatorWrapper(source, schemas) {
  const request = schemas.BrokerRequest;
  const presentation = schemas.Presentation;
  const event = schemas.BrokerEvent;
  const error = schemas.Error;
  const decision = schemas.Decision;
  const page = schemas.RequestPage;
  const generated = `// Generated from protocol/openapi/operator-v1.yaml. Do not edit.
import type { components } from "./openapi-operator-v1.js";

export const OPERATOR_V1_SCHEMA_SHA256 = ${JSON.stringify(createHash("sha256").update(source).digest("hex"))};
export const operatorV1 = ${JSON.stringify(
    {
      apiVersion: schemas.Descriptor.properties.api_version.const,
      statuses: schemas.Status.enum,
      actions: schemas.Action.enum,
      risks: presentation.properties.risk.enum,
      eventKinds: event.properties.kind.enum,
      errorCodes: error.properties.code.enum,
      limits: {
        id: request.properties.id.maxLength,
        requester: request.properties.requester.maxLength,
        operation: request.properties.operation.maxLength,
        reason: request.properties.request_reason.maxLength,
        actor: request.properties.decided_by.maxLength,
        title: presentation.properties.title.maxLength,
        summary: presentation.properties.summary.maxLength,
        facts: presentation.properties.facts.maxItems,
        factLabel: schemas.Fact.properties.label.maxLength,
        factValue: schemas.Fact.properties.value.maxLength,
        cursor: event.properties.cursor.maxLength,
        page: page.properties.requests.maxItems,
        idempotencyKey: decision.properties.idempotency_key.maxLength,
        errorMessage: error.properties.message.maxLength,
        correlationId: error.properties.correlation_id.maxLength,
      },
    },
    null,
    2,
  )} as const;

export type Decision = components["schemas"]["Decision"];
export type Discovery = components["schemas"]["Descriptor"];
export type ErrorEnvelope = components["schemas"]["ErrorEnvelope"];
export type BrokerEvent = components["schemas"]["BrokerEvent"];
export type RequestPage = components["schemas"]["RequestPage"];
export type Presentation = components["schemas"]["Presentation"];
export type BrokerRequest = components["schemas"]["BrokerRequest"];
`;
  emit(
    path.join(root, "plugins/openclaw/src/generated/operator-v1.ts"),
    await format(generated, { parser: "typescript" }),
  );
}

async function emitOperatorSchemas(components) {
  const names = [
    "Descriptor",
    "Health",
    "BrokerRequest",
    "RequestPage",
    "BrokerEvent",
    "ErrorEnvelope",
  ];
  const declarations = names.map((name) => {
    const schema = {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      $id: `https://brokerkit.dev/schema/operator/v1/runtime/${name}`,
      ...rewriteRefs(structuredClone(components[name])),
      $defs: rewriteRefs(structuredClone(components)),
    };
    return `export const ${name}Schema = ${JSON.stringify(schema)} as const;`;
  });
  emit(
    path.join(root, "plugins/openclaw/src/generated/operator-schemas.ts"),
    await format(
      `// Generated from protocol/openapi/operator-v1.yaml. Do not edit.\n${declarations.join("\n")}`,
      { parser: "typescript" },
    ),
  );
}

function emit(filename, contents) {
  if (check) {
    let current = "";
    try {
      current = readFileSync(filename, "utf8");
    } catch {}
    if (current !== contents) {
      process.stderr.write(`${path.relative(root, filename)} is stale\n`);
      stale = true;
    }
    return;
  }
  mkdirSync(path.dirname(filename), { recursive: true });
  writeFileSync(filename, contents);
}
