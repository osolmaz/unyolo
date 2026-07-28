import { describe, expect, it } from "vitest";
import { parseConfig } from "./config.js";

const valid = {
  mode: "direct" as const,
  brokers: [
    {
      id: "hf",
      label: "Hugging Face",
      endpoint: "http://127.0.0.1:8081",
      operatorCredential: {
        source: "env",
        provider: "default",
        id: "HF_OPERATOR_SECRET",
      },
    },
  ],
};
describe("parseConfig", () => {
  it("accepts strict structured SecretRefs", () => {
    const parsed = parseConfig(valid);
    expect(parsed.mode).toBe("direct");
    if (parsed.mode !== "direct") throw new Error("unexpected mode");
    expect(parsed.brokers[0]?.requestTimeoutMs).toBe(10000);
  });
  it("rejects duplicate ids, literal secrets, unknown fields, and remote plaintext", () => {
    expect(() =>
      parseConfig({ brokers: [valid.brokers[0], valid.brokers[0]] }),
    ).toThrow();
    expect(() =>
      parseConfig({
        brokers: [{ ...valid.brokers[0], operatorCredential: "secret" }],
      }),
    ).toThrow();
    expect(() => parseConfig({ ...valid, extra: true })).toThrow();
    expect(() =>
      parseConfig({
        brokers: [{ ...valid.brokers[0], endpoint: "http://example.com" }],
      }),
    ).toThrow();
  });
  it("accepts only normalized same-origin delegated web paths", () => {
    expect(
      parseConfig({
        mode: "delegated-web",
        delegatedWeb: { basePath: "/trusted-host/api/unyolo" },
      }),
    ).toEqual({
      mode: "delegated-web",
      delegatedWeb: { basePath: "/trusted-host/api/unyolo" },
    });
    for (const basePath of [
      "https://example.com/api",
      "//example.com/api",
      "/api/../admin",
      "/api/%2e%2e/admin",
      "/api?token=x",
      "/api/",
    ]) {
      expect(() =>
        parseConfig({
          mode: "delegated-web",
          delegatedWeb: { basePath },
        }),
      ).toThrow();
    }
  });
  it("defaults empty plugin config to skills-only mode", () => {
    expect(parseConfig(undefined)).toEqual({ mode: "skills-only" });
    expect(parseConfig({})).toEqual({ mode: "skills-only" });
    expect(parseConfig({ mode: "skills-only" })).toEqual({
      mode: "skills-only",
    });
  });
  it("rejects missing direct mode and fields from another mode", () => {
    expect(() => parseConfig({ brokers: valid.brokers })).toThrow();
    expect(() =>
      parseConfig({
        mode: "delegated-web",
        delegatedWeb: { basePath: "/api/unyolo" },
        brokers: valid.brokers,
      }),
    ).toThrow();
    expect(() =>
      parseConfig({ mode: "skills-only", brokers: valid.brokers }),
    ).toThrow();
  });
});
