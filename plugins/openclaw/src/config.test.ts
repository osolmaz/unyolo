import { describe, expect, it } from "vitest";
import { parseConfig } from "./config.js";

const valid = {
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
    expect(parseConfig(valid).brokers[0]?.requestTimeoutMs).toBe(10000);
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
});
