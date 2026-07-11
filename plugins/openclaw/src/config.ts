import { z } from "zod";

const secretRef = z
  .object({
    source: z.enum(["env", "file", "exec"]),
    provider: z.string().min(1).max(64),
    id: z.string().min(1).max(512),
  })
  .strict();
const broker = z
  .object({
    id: z.string().regex(/^[a-z][a-z0-9-]{0,63}$/),
    label: z.string().trim().min(1).max(80),
    endpoint: z.url(),
    operatorCredential: secretRef,
    requestTimeoutMs: z.number().int().min(1000).max(60000).default(10000),
  })
  .strict();
const directConfig = z
  .object({
    mode: z.literal("direct"),
    brokers: z.array(broker).min(1).max(32),
    pollIntervalMs: z.number().int().min(5000).max(300000).default(30000),
    notificationConcurrency: z.number().int().min(1).max(16).default(4),
  })
  .strict()
  .superRefine((value, ctx) => {
    const seen = new Set<string>();
    for (const [index, source] of value.brokers.entries()) {
      if (seen.has(source.id))
        ctx.addIssue({
          code: "custom",
          path: ["brokers", index, "id"],
          message: "broker ids must be unique",
        });
      seen.add(source.id);
      const endpoint = new URL(source.endpoint);
      if (
        endpoint.username ||
        endpoint.password ||
        endpoint.search ||
        endpoint.hash ||
        !["http:", "https:"].includes(endpoint.protocol)
      )
        ctx.addIssue({
          code: "custom",
          path: ["brokers", index, "endpoint"],
          message: "endpoint must be a credential-free HTTP URL",
        });
      if (
        endpoint.protocol === "http:" &&
        !["127.0.0.1", "localhost", "::1"].includes(endpoint.hostname)
      )
        ctx.addIssue({
          code: "custom",
          path: ["brokers", index, "endpoint"],
          message: "plaintext HTTP is limited to loopback",
        });
    }
  });

const delegatedWebConfig = z
  .object({
    mode: z.literal("delegated-web"),
    delegatedWeb: z
      .object({
        basePath: z.string().superRefine((value, ctx) => {
          if (!validDelegatedBasePath(value)) {
            ctx.addIssue({
              code: "custom",
              message:
                "delegated web basePath must be a normalized same-origin absolute path",
            });
          }
        }),
      })
      .strict(),
  })
  .strict();

export const configSchema = z.discriminatedUnion("mode", [
  directConfig,
  delegatedWebConfig,
]);

export type PluginConfig = z.infer<typeof configSchema>;
export type DirectPluginConfig = z.infer<typeof directConfig>;
export type BrokerConfig = DirectPluginConfig["brokers"][number];
export function parseConfig(value: unknown): PluginConfig {
  return configSchema.parse(value);
}

function validDelegatedBasePath(value: string): boolean {
  if (
    value.length < 2 ||
    value.length > 256 ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.endsWith("/") ||
    /[?#\\]/u.test(value) ||
    hasControlCharacter(value)
  ) {
    return false;
  }
  try {
    const decoded = decodeURIComponent(value);
    if (decoded !== value || decoded.includes("..") || decoded.includes("\\")) {
      return false;
    }
  } catch {
    return false;
  }
  return value
    .split("/")
    .every(
      (segment, index) => index === 0 || /^[A-Za-z0-9._~-]+$/u.test(segment),
    );
}

function hasControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code < 32 || code === 127;
  });
}
