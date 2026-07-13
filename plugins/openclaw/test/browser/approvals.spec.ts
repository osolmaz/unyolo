import { expect, test } from "@playwright/test";

const snapshot = {
  sources: [
    {
      id: "hf",
      label: "Hugging Face",
      healthy: true,
      last_sync_at: "2026-07-11T00:00:00Z",
    },
  ],
  requests: [
    {
      source_id: "hf",
      source_label: "Hugging Face",
      handle: "opaque-request-handle-1",
      request: {
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
    },
    {
      source_id: "hf",
      source_label: "Hugging Face",
      handle: "active-request-handle-1",
      request: {
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
    },
  ],
  api_version: "brokerkit.io/operator-ui/v1",
  cursor: "browser-epoch.1",
  synchronized_at: "2026-07-11T00:00:00Z",
  delivery_failures: 0,
};
const pendingRequest = snapshot.requests[0]!;

test.beforeEach(async ({ page }) => {
  await page.route("**/plugins/brokerkit/api/v1/snapshot", (route) =>
    route.fulfill({ json: snapshot }),
  );
  await page.route("**/events?*", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 250));
    await route.fulfill({
      json: {
        api_version: "brokerkit.io/operator-ui/v1",
        cursor: snapshot.cursor,
        changed: false,
      },
    });
  });
  await page.route(
    "**/plugins/brokerkit/api/v1/requests/*/approve",
    async (route) => {
      expect(route.request().headers().authorization).toBe(
        "Bearer test-capability-that-is-long-enough-1234",
      );
      expect(route.request().postDataJSON()).toEqual({
        expectedRevision: 1,
        constraints: { durationSeconds: 300, maxUses: 1 },
      });
      await route.fulfill({
        json: {
          ...pendingRequest,
          request: { ...pendingRequest.request, status: "active" },
        },
      });
    },
  );
});
test("renders a bounded capability-protected approval surface", async ({
  page,
}, testInfo) => {
  await page.goto(
    `/plugins/brokerkit/ui/#${bootstrap({ version: 1, mode: "direct", capability: "test-capability-that-is-long-enough-1234" })}`,
  );
  await expect(page.getByRole("heading", { name: "Approvals" })).toBeVisible();
  await expect(page.getByText("Hugging Face repository write")).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Cancel" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Revoke" })).toBeVisible();
  await page.getByRole("button", { name: "Deny" }).click();
  await expect(
    page.getByRole("dialog", { name: "Deny request" }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(
    page.getByRole("dialog", { name: "Deny request" }),
  ).not.toBeVisible();
  await page.getByRole("button", { name: "Approve" }).click();
  const dialog = page.getByRole("dialog", { name: "Approve request" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText("at revision 1")).toBeVisible();
  expect(
    await dialog.evaluate((element) => {
      const box = element.getBoundingClientRect();
      return (
        box.left >= 0 &&
        box.top >= 0 &&
        box.right <= window.innerWidth &&
        box.bottom <= window.innerHeight
      );
    }),
  ).toBe(true);
  await page.screenshot({
    path: testInfo.outputPath("approval-dialog.png"),
    fullPage: true,
  });
  await dialog.getByRole("button", { name: "Approve" }).click();
  await expect(dialog).not.toBeVisible();
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

test("preserves an unlimited-use approval until expiry", async ({ page }) => {
  const unlimited = {
    ...snapshot,
    requests: [
      {
        ...pendingRequest,
        request: {
          ...pendingRequest.request,
          requested_max_uses: null,
          approval_bounds: { max_duration_seconds: 300, max_uses: null },
        },
      },
    ],
  };
  await page.route("**/plugins/brokerkit/api/v1/snapshot", (route) =>
    route.fulfill({ json: unlimited }),
  );
  await page.route(
    "**/plugins/brokerkit/api/v1/requests/*/approve",
    async (route) => {
      expect(route.request().postDataJSON()).toEqual({
        expectedRevision: 1,
        constraints: { durationSeconds: 300, maxUses: null },
      });
      await route.fulfill({
        json: {
          ...unlimited.requests[0],
          request: { ...unlimited.requests[0]!.request, status: "active" },
        },
      });
    },
  );
  await page.goto(
    `/plugins/brokerkit/ui/#${bootstrap({ version: 1, mode: "direct", capability: "test-capability-that-is-long-enough-1234" })}`,
  );
  await expect(page.getByText("Unlimited uses")).toBeVisible();
  await page.getByRole("button", { name: "Approve" }).click();
  const dialog = page.getByRole("dialog", { name: "Approve request" });
  await expect(
    dialog.getByRole("checkbox", { name: "Unlimited until expiry" }),
  ).toBeChecked();
  await dialog.getByRole("button", { name: "Approve" }).click();
  await expect(dialog).not.toBeVisible();
});

test("uses delegated web session authority without exposing it in the URL", async ({
  page,
}) => {
  const token = "delegated-decision-token-that-is-long-enough";
  await page.route("**/trusted-host/api/brokerkit/session", (route) =>
    route.fulfill({
      json: {
        api_version: "brokerkit.io/delegated-web/v1",
        token,
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        access: "decide",
        renewal_transport: "direct",
      },
    }),
  );
  await page.route("**/trusted-host/api/brokerkit/snapshot", async (route) => {
    expect(route.request().headers().authorization).toBe(`Bearer ${token}`);
    await route.fulfill({ json: snapshot });
  });
  await page.goto(
    `/plugins/brokerkit/ui/#${bootstrap({ version: 1, mode: "delegated-web", basePath: "/trusted-host/api/brokerkit" })}`,
  );
  await expect(page.getByText("Hugging Face repository write")).toBeVisible();
  await expect(page).not.toHaveURL(/#/);
});

test("reconciles cursor changes without resetting an open decision", async ({
  page,
}) => {
  await page.unroute("**/plugins/brokerkit/api/v1/snapshot");
  await page.unroute("**/events?*");
  const current = structuredClone(snapshot);
  let release: (() => void) | undefined;
  let eventCalls = 0;
  await page.route("**/plugins/brokerkit/api/v1/snapshot", (route) =>
    route.fulfill({ json: current }),
  );
  await page.route("**/events?*", async (route) => {
    eventCalls += 1;
    if (eventCalls === 1)
      await new Promise<void>((resolve) => {
        release = resolve;
      });
    else await new Promise((resolve) => setTimeout(resolve, 250));
    await route.fulfill({
      json: {
        api_version: "brokerkit.io/operator-ui/v1",
        cursor: current.cursor,
        changed: eventCalls === 1,
      },
    });
  });
  await page.goto(
    `/plugins/brokerkit/ui/#${bootstrap({ version: 1, mode: "direct", capability: "test-capability-that-is-long-enough-1234" })}`,
  );
  await page.getByRole("button", { name: "Approve" }).click();
  const dialog = page.getByRole("dialog", { name: "Approve request" });
  const duration = dialog.getByLabel("Duration (seconds)");
  await duration.fill("120");
  await expect.poll(() => eventCalls).toBe(1);
  const added = structuredClone(pendingRequest);
  added.handle = "second-pending-request-1";
  added.request.id = "request-3";
  added.request.presentation.title = "New protected request";
  current.cursor = "browser-epoch.2";
  current.synchronized_at = "2026-07-11T00:00:01Z";
  current.requests.push(added);
  release?.();
  await expect(page.getByText("New protected request")).toBeVisible();
  await expect(dialog).toBeVisible();
  await expect(duration).toHaveValue("120");
});

test("accepts only strict parent refresh invalidations", async ({ page }) => {
  let snapshots = 0;
  await page.unroute("**/plugins/brokerkit/api/v1/snapshot");
  await page.route("**/plugins/brokerkit/api/v1/snapshot", async (route) => {
    snapshots += 1;
    await route.fulfill({ json: snapshot });
  });
  await page.goto(
    `/plugins/brokerkit/ui/#${bootstrap({ version: 1, mode: "direct", capability: "test-capability-that-is-long-enough-1234" })}`,
  );
  await expect(page.getByText("Hugging Face repository write")).toBeVisible();
  await page.evaluate(() =>
    window.postMessage(
      { type: "brokerkit.operator-ui.invalidate", version: 1, extra: true },
      "*",
    ),
  );
  await page.waitForTimeout(100);
  expect(snapshots).toBe(1);
  await page.evaluate(() =>
    window.postMessage(
      { type: "brokerkit.operator-ui.invalidate", version: 1 },
      "*",
    ),
  );
  await expect.poll(() => snapshots).toBe(2);
});

test("decides with a trusted embedded session inside the sandboxed approval frame", async ({
  page,
}) => {
  const token = "embedded-decision-token-that-is-long-enough";
  const encodedBootstrap = bootstrap({
    version: 1,
    mode: "delegated-web",
    basePath: "/trusted-host/api/brokerkit",
  });
  const encodedSession = bootstrap({
    api_version: "brokerkit.io/delegated-web/v1",
    token,
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    access: "decide",
    renewal_transport: "direct",
  });
  await page.route("**/plugins/brokerkit/ui/**", async (route) => {
    const response = await route.fetch();
    await route.fulfill({
      response,
      headers: {
        ...response.headers(),
        "access-control-allow-origin": "null",
        "access-control-allow-private-network": "true",
        "content-security-policy":
          "sandbox allow-scripts; default-src 'self'; script-src 'self' http://127.0.0.1:4179; style-src 'self' 'unsafe-inline' http://127.0.0.1:4179; connect-src http://127.0.0.1:4179; img-src 'self' data:",
      },
    });
  });
  await page.route("**/plugins/brokerkit/ui/", async (route) => {
    const response = await route.fetch();
    const body = (await response.text()).replace(
      "<head>",
      `<head><meta name="brokerkit-delegated-session" content="${encodedSession}" />`,
    );
    await route.fulfill({
      response,
      body,
      headers: {
        ...response.headers(),
        "access-control-allow-origin": "null",
        "access-control-allow-private-network": "true",
        "content-security-policy":
          "sandbox allow-scripts; default-src 'self'; script-src 'self' http://127.0.0.1:4179; style-src 'self' 'unsafe-inline' http://127.0.0.1:4179; connect-src http://127.0.0.1:4179; img-src 'self' data:",
      },
    });
  });
  await page.route("**/trusted-host/api/brokerkit/snapshot", async (route) => {
    expect(route.request().headers().authorization).toBe(`Bearer ${token}`);
    await route.fulfill({
      json: snapshot,
      headers: { "access-control-allow-origin": "null" },
    });
  });
  let decisionReceived = false;
  await page.route(
    "**/trusted-host/api/brokerkit/requests/*/deny",
    async (route) => {
      expect(route.request().headers().authorization).toBe(`Bearer ${token}`);
      expect(route.request().postDataJSON()).toEqual({ expectedRevision: 1 });
      decisionReceived = true;
      await route.fulfill({
        json: {
          ...pendingRequest,
          request: { ...pendingRequest.request, status: "denied" },
        },
        headers: { "access-control-allow-origin": "null" },
      });
    },
  );

  await page.goto("/");
  await page.setContent(
    `<iframe title="Approvals" sandbox="allow-scripts" src="http://127.0.0.1:4179/plugins/brokerkit/ui/#${encodedBootstrap}"></iframe>`,
  );
  const parentUrl = page.url();

  const approvals = page.frameLocator('iframe[title="Approvals"]');
  await expect(
    approvals.getByText("Hugging Face repository write"),
  ).toBeVisible();
  await expect(
    approvals.getByRole("button", { name: "Approve" }),
  ).toBeVisible();
  await approvals.getByRole("button", { name: "Deny" }).first().click();
  const dialog = approvals.getByRole("dialog", { name: "Deny request" });
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "Deny" }).click();
  await expect(dialog).not.toBeVisible();
  expect(decisionReceived).toBe(true);
  await expect(page).toHaveURL(parentUrl);
});

test("keeps framed delegated UI authority-free until top-level navigation", async ({
  page,
}) => {
  const encodedBootstrap = bootstrap({
    version: 1,
    mode: "delegated-web",
    basePath: "/trusted-host/api/brokerkit",
  });
  await page.route("**/plugins/brokerkit/ui/", async (route) => {
    const response = await route.fetch();
    const body = (await response.text()).replace(
      "<head>",
      '<head><meta name="brokerkit-delegated-top-level" />',
    );
    await route.fulfill({ response, body });
  });
  await page.setContent(
    `<iframe title="Approvals" src="http://127.0.0.1:4179/plugins/brokerkit/ui/#${encodedBootstrap}"></iframe>`,
  );
  const launcher = page.frameLocator('iframe[title="Approvals"]');
  await expect(
    launcher.getByRole("button", { name: "Open approvals" }),
  ).toBeVisible();
  await expect(
    launcher.getByText("Hugging Face repository write"),
  ).not.toBeVisible();
  const openMessage = page.evaluate(
    () =>
      new Promise<Record<string, unknown>>((resolve) => {
        window.addEventListener(
          "message",
          (event) => resolve(event.data as Record<string, unknown>),
          { once: true },
        );
      }),
  );
  await launcher.getByRole("button", { name: "Open approvals" }).click();
  await expect(openMessage).resolves.toMatchObject({
    type: "brokerkit.delegated-web.open",
    version: 1,
    nonce: expect.stringMatching(/^[a-f0-9]{32}$/u),
  });
});

function bootstrap(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}
