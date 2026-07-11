import { describe, expect, it, vi } from "vitest";
import { registerBrokerKit } from "../index.js";

describe("plugin registration", () => {
  it("registers only the tab and static route in delegated web mode", () => {
    const registerService = vi.fn();
    const registerCommand = vi.fn();
    const registerHttpRoute = vi.fn();
    const registerControlUiDescriptor = vi.fn();
    registerBrokerKit({
      pluginConfig: {
        mode: "delegated-web",
        delegatedWeb: { basePath: "/mlclaw/api/brokerkit" },
      },
      session: { controls: { registerControlUiDescriptor } },
      registerService,
      registerCommand,
      registerHttpRoute,
      rootDir: "/tmp/plugin",
    } as never);
    expect(registerService).not.toHaveBeenCalled();
    expect(registerCommand).not.toHaveBeenCalled();
    expect(registerHttpRoute).toHaveBeenCalledOnce();
    expect(registerControlUiDescriptor).toHaveBeenCalledWith(
      expect.objectContaining({
        surface: "tab",
        requiredScopes: ["operator.approvals"],
      }),
    );
    const path = registerControlUiDescriptor.mock.calls[0]?.[0]?.path as string;
    const bootstrap = JSON.parse(
      Buffer.from(path.split("#")[1] ?? "", "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    expect(bootstrap).toEqual({
      version: 1,
      mode: "delegated-web",
      basePath: "/mlclaw/api/brokerkit",
    });
  });
});
