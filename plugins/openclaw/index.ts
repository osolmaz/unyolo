import { randomBytes } from "node:crypto";
import {
  definePluginEntry,
  type OpenClawPluginApi,
} from "openclaw/plugin-sdk/plugin-entry";
import { resolveConfiguredSecretInputString } from "openclaw/plugin-sdk/secret-input-runtime";
import { handleCommand } from "./src/commands.js";
import { parseConfig, type BrokerConfig } from "./src/config.js";
import { createHttpHandler } from "./src/http.js";
import { BrokerRuntime } from "./src/runtime.js";

const configSchema = { parse: parseConfig };

type DirectBootstrap = {
  version: 1;
  mode: "direct";
  capability: string;
};
type DelegatedBootstrap = {
  version: 1;
  mode: "delegated-web";
  basePath: string;
};

export function registerBrokerKit(api: OpenClawPluginApi): void {
  const config = parseConfig(api.pluginConfig);
  const capability =
    config.mode === "direct"
      ? randomBytes(32).toString("base64url")
      : undefined;
  const bootstrap: DirectBootstrap | DelegatedBootstrap =
    config.mode === "direct"
      ? {
          version: 1,
          mode: "direct",
          capability: requiredCapability(capability),
        }
      : {
          version: 1,
          mode: "delegated-web",
          basePath: config.delegatedWeb.basePath,
        };
  let runtime: BrokerRuntime | undefined;
  const requireRuntime = () => {
    if (!runtime) throw new Error("BrokerKit runtime is not running");
    return runtime;
  };
  api.session.controls.registerControlUiDescriptor({
    surface: "tab",
    id: "brokerkit",
    label: "Approvals",
    description: "Review pending BrokerKit requests.",
    icon: "shield-check",
    group: "control",
    requiredScopes: ["operator.approvals"],
    path: `/plugins/brokerkit/ui/#${encodeUiBootstrap(bootstrap)}`,
  });
  if (config.mode === "direct") {
    api.registerService({
      id: "brokerkit",
      start: async (ctx) => {
        runtime = new BrokerRuntime(config, {
          resolveCredential: (source) => resolveCredential(api, source),
          deliver: async (subscription, text) => {
            const adapter = await api.runtime.channel.outbound.loadAdapter(
              subscription.channel,
            );
            if (!adapter?.sendText)
              throw new Error("channel does not support text delivery");
            await adapter.sendText({
              cfg: api.config,
              to: subscription.target,
              text,
              ...(subscription.accountId
                ? { accountId: subscription.accountId }
                : {}),
              ...(subscription.threadId
                ? { threadId: subscription.threadId }
                : {}),
            });
          },
          log: (level, message) => api.logger[level]?.(message),
        });
        await runtime.start(ctx.stateDir);
      },
      stop: async () => {
        await runtime?.stop();
        runtime = undefined;
      },
    });
    api.registerCommand({
      name: "brokerkit",
      description: "Review and decide BrokerKit approval requests.",
      acceptsArgs: true,
      requireAuth: true,
      requiredScopes: ["operator.approvals"],
      handler: (ctx) => handleCommand(requireRuntime(), ctx),
    });
  }
  api.registerHttpRoute({
    path: "/plugins/brokerkit",
    auth: "plugin",
    match: "prefix",
    handler: createHttpHandler(
      config.mode === "direct" ? requireRuntime : undefined,
      api.rootDir ?? process.cwd(),
      capability,
    ),
  });
}

function encodeUiBootstrap(
  value: DirectBootstrap | DelegatedBootstrap,
): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function requiredCapability(value: string | undefined): string {
  if (!value) throw new Error("BrokerKit UI capability was not initialized");
  return value;
}

async function resolveCredential(
  api: OpenClawPluginApi,
  source: BrokerConfig,
): Promise<string> {
  const resolved = await resolveConfiguredSecretInputString({
    config: api.config,
    env: process.env,
    value: source.operatorCredential,
    path: `plugins.entries.brokerkit.config.brokers.${source.id}.operatorCredential`,
  });
  if (!resolved.value)
    throw new Error(`operator credential unavailable for ${source.id}`);
  return resolved.value;
}

export default definePluginEntry({
  id: "brokerkit",
  name: "BrokerKit",
  description: "Provider-neutral BrokerKit approvals",
  configSchema,
  register: registerBrokerKit,
});
