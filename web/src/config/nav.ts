export type NavEntry = {
  /** Slug of the doc in the `docs` collection, without a leading slash. */
  slug: string;
  /** Overrides the collection's `navLabel`/`title` for this position. */
  label?: string;
};

export type NavSection = {
  title: string;
  entries: NavEntry[];
};

/**
 * Ordered sidebar for the documentation. This file is the single source of
 * truth for ordering, breadcrumbs, and previous/next links, so a page that is
 * missing here is unreachable from the sidebar even if the Markdown exists.
 */
export const sidebar: NavSection[] = [
  {
    title: "Get started",
    entries: [
      { slug: "get-started/overview", label: "Overview" },
      { slug: "get-started/why-brokerkit", label: "Why BrokerKit" },
      { slug: "get-started/quickstart", label: "Quickstart" },
      { slug: "get-started/installation", label: "Installation" },
    ],
  },
  {
    title: "Concepts",
    entries: [
      { slug: "concepts/architecture", label: "Architecture" },
      { slug: "concepts/vocabulary", label: "Request vocabulary" },
      { slug: "concepts/policy", label: "Policy engine" },
      { slug: "concepts/grants", label: "Grants" },
      { slug: "concepts/approvals", label: "Approvals" },
      { slug: "concepts/operations", label: "Agent operations" },
      { slug: "concepts/audit-logging", label: "Audit logging" },
    ],
  },
  {
    title: "Guides",
    entries: [
      { slug: "guides/write-a-policy", label: "Write a policy" },
      { slug: "guides/connect-an-agent", label: "Connect an agent" },
      { slug: "guides/brokered-git", label: "Broker Git traffic" },
      { slug: "guides/mcp-server", label: "Run an MCP server" },
      { slug: "guides/telegram-approvals", label: "Approve from Telegram" },
      { slug: "guides/rotate-credentials", label: "Rotate credentials" },
      { slug: "guides/verify-isolation", label: "Verify host isolation" },
    ],
  },
  {
    title: "Brokers",
    entries: [
      { slug: "brokers/github", label: "gh-broker" },
      { slug: "brokers/hugging-face", label: "hf-broker" },
      { slug: "brokers/sudo", label: "sudo-broker" },
      { slug: "brokers/openclaw", label: "OpenClaw plugin" },
    ],
  },
  {
    title: "Build a broker",
    entries: [
      { slug: "build/framework", label: "Framework overview" },
      { slug: "build/registry", label: "Provider registry" },
      { slug: "build/conformance", label: "Conformance tests" },
    ],
  },
  {
    title: "Deploy",
    entries: [
      { slug: "deploy/host-deployment", label: "Host deployment" },
      { slug: "deploy/systemd", label: "systemd and launchd" },
      { slug: "deploy/runtime-bundles", label: "Runtime bundles" },
      { slug: "deploy/admission-control", label: "Admission control" },
    ],
  },
  {
    title: "Operate",
    entries: [
      { slug: "operate/observability", label: "Metrics and logs" },
      { slug: "operate/state", label: "State maintenance" },
      { slug: "operate/failure-drills", label: "Failure drills" },
    ],
  },
  {
    title: "Security",
    entries: [
      { slug: "security/security-model", label: "Security model" },
      { slug: "security/threat-model", label: "Threat model" },
    ],
  },
  {
    title: "Reference",
    entries: [
      { slug: "reference/cli", label: "CLI commands" },
      { slug: "reference/policy-schema", label: "Policy schema" },
      { slug: "reference/agent-v1", label: "Agent V1 API" },
      { slug: "reference/operator-v1", label: "Operator V1 API" },
      { slug: "reference/configuration", label: "Configuration" },
      { slug: "reference/audit-events", label: "Audit events" },
    ],
  },
];

/** Flattened reading order, used for previous/next navigation. */
export const readingOrder: { slug: string; label: string; section: string }[] =
  sidebar.flatMap((section) =>
    section.entries.map((entry) => ({
      slug: entry.slug,
      label: entry.label ?? entry.slug,
      section: section.title,
    })),
  );

export function neighbours(slug: string) {
  const index = readingOrder.findIndex((entry) => entry.slug === slug);
  if (index === -1) return { prev: undefined, next: undefined };
  return {
    prev: index > 0 ? readingOrder[index - 1] : undefined,
    next: index < readingOrder.length - 1 ? readingOrder[index + 1] : undefined,
  };
}

export function sectionOf(slug: string): string | undefined {
  return readingOrder.find((entry) => entry.slug === slug)?.section;
}

export const GITHUB_REPO = "https://github.com/osolmaz/brokerkit";
// Swap for a personal site if you would rather the credit point there.
export const AUTHOR_URL = "https://github.com/osolmaz";
export const GITHUB_EDIT_BASE = `${GITHUB_REPO}/edit/main/web/src/content/docs`;
