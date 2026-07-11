import { expect, test } from "@playwright/test";

const snapshot = {
  sources: [
    {
      id: "hf",
      label: "Hugging Face",
      healthy: true,
      lastSyncAt: "2026-07-11T00:00:00Z",
    },
  ],
  requests: [
    {
      sourceId: "hf",
      sourceLabel: "Hugging Face",
      handle: "opaque-request-handle",
      id: "request-1",
      revision: 1,
      requester: "bob",
      operation: "git.push.force",
      status: "pending",
      requested_at: "2026-07-11T00:00:00Z",
      pending_expires_at: "2026-07-11T00:10:00Z",
      requested_duration_seconds: 300,
      requested_max_uses: 1,
      granted_max_uses: null,
      used_count: 0,
      presentation: {
        risk: "critical",
        title: "Hugging Face repository write",
        summary: "Approve one bounded update to the protected branch.",
        facts: [
          { label: "Repository", value: "osolmaz/model" },
          { label: "Ref", value: "refs/heads/main" },
        ],
      },
      allowed_actions: ["approve", "deny", "cancel"],
      approval_bounds: { max_duration_seconds: 300, max_uses: 1 },
    },
    {
      sourceId: "hf",
      sourceLabel: "Hugging Face",
      handle: "active-request-handle",
      id: "request-2",
      revision: 2,
      requester: "bob",
      operation: "repo.update",
      status: "active",
      requested_at: "2026-07-11T00:00:00Z",
      active_expires_at: "2026-07-11T01:00:00Z",
      requested_duration_seconds: 3600,
      requested_max_uses: 3,
      granted_max_uses: 3,
      used_count: 1,
      presentation: {
        risk: "high",
        title: "Active repository grant",
        facts: [{ label: "Repository", value: "osolmaz/model" }],
      },
      allowed_actions: ["revoke"],
      approval_bounds: { max_duration_seconds: 3600, max_uses: 3 },
    },
  ],
  synchronizedAt: "2026-07-11T00:00:00Z",
};

test.beforeEach(async ({ page }) => {
  await page.route("**/plugins/brokerkit/api/v1/snapshot", (route) =>
    route.fulfill({ json: snapshot }),
  );
});
test("renders a bounded capability-protected approval surface", async ({
  page,
}, testInfo) => {
  await page.goto(
    `/#${bootstrap({ version: 1, mode: "direct", capability: "test-capability-that-is-long-enough-1234" })}`,
  );
  await expect(page.getByRole("heading", { name: "Approvals" })).toBeVisible();
  await expect(page.getByText("Hugging Face repository write")).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Cancel" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Revoke" })).toBeVisible();
  await expect(page).not.toHaveURL(/#/);
  const overflow = await page.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  expect(overflow).toBe(false);
  await page.screenshot({
    path: testInfo.outputPath("approvals.png"),
    fullPage: true,
  });
});

test("uses delegated web session authority without exposing it in the URL", async ({
  page,
}) => {
  const token = "delegated-decision-token-that-is-long-enough";
  await page.route("**/mlclaw/api/brokerkit/session", (route) =>
    route.fulfill({
      json: {
        api_version: "brokerkit.io/delegated-web/v1",
        actor: "osolmaz",
        decision_token: token,
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      },
    }),
  );
  await page.route("**/mlclaw/api/brokerkit/snapshot", async (route) => {
    expect(route.request().headers().authorization).toBe(`Bearer ${token}`);
    await route.fulfill({ json: snapshot });
  });
  await page.goto(
    `/#${bootstrap({ version: 1, mode: "delegated-web", basePath: "/mlclaw/api/brokerkit" })}`,
  );
  await expect(page.getByText("Hugging Face repository write")).toBeVisible();
  await expect(page).not.toHaveURL(/#/);
});

function bootstrap(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}
