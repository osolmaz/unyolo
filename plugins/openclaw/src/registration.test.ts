import { describe, expect, it, vi } from "vitest";
import { registerunYOLO } from "../index.js";

describe("plugin registration", () => {
  it("registers no approval surfaces in the default skills-only mode", () => {
    const registerService = vi.fn();
    const registerCommand = vi.fn();
    const registerHttpRoute = vi.fn();
    registerunYOLO({
      pluginConfig: {},
      registerService,
      registerCommand,
      registerHttpRoute,
    } as never);
    expect(registerService).not.toHaveBeenCalled();
    expect(registerCommand).not.toHaveBeenCalled();
    expect(registerHttpRoute).not.toHaveBeenCalled();
  });
  it("registers only the tab and static route in delegated web mode", () => {
    const registerService = vi.fn();
    const registerCommand = vi.fn();
    const registerHttpRoute = vi.fn();
    const registerControlUiDescriptor = vi.fn();
    registerunYOLO({
      pluginConfig: {
        mode: "delegated-web",
        delegatedWeb: { basePath: "/trusted-host/api/unyolo" },
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
      basePath: "/trusted-host/api/unyolo",
    });
  });
  it("rotates a 256-bit direct UI capability on each registration", () => {
    const paths: string[] = [];
    for (let index = 0; index < 2; index += 1) {
      const registerService = vi.fn();
      const registerCommand = vi.fn();
      const registerHttpRoute = vi.fn();
      registerunYOLO({
        pluginConfig: {
          mode: "direct",
          brokers: [
            {
              id: "source",
              label: "Source",
              endpoint: "http://127.0.0.1:8080",
              operatorCredential: {
                source: "env",
                provider: "default",
                id: "SOURCE_SECRET",
              },
            },
          ],
        },
        session: {
          controls: {
            registerControlUiDescriptor: (descriptor: { path: string }) =>
              paths.push(descriptor.path),
          },
        },
        registerService,
        registerCommand,
        registerHttpRoute,
        rootDir: "/tmp/plugin",
      } as never);
      expect(registerService).toHaveBeenCalledOnce();
      expect(registerCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "unyolo",
          requireAuth: true,
          requiredScopes: ["operator.approvals"],
        }),
      );
      expect(registerHttpRoute).toHaveBeenCalledOnce();
    }
    const capabilities = paths.map((value) => {
      const bootstrap = JSON.parse(
        Buffer.from(value.split("#")[1] ?? "", "base64url").toString("utf8"),
      ) as { capability: string };
      expect(bootstrap.capability).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      return bootstrap.capability;
    });
    expect(capabilities[0]).not.toBe(capabilities[1]);
  });
});
