# unYOLO documentation site

This directory contains the Astro site for unYOLO. Every page is prerendered,
and the site has no runtime backend. Client-side JavaScript is limited to
navigation, search, theme switching, and code-block copy buttons.

## Working on it

The site is a workspace package, so install from the repository root:

```sh
pnpm install --filter unyolo-web
```

Then, from this directory:

```sh
pnpm dev      # development server with hot reload
pnpm build    # static build into dist/
pnpm preview  # serve the built output
pnpm check    # Astro and TypeScript diagnostics
```

Node 24.18.0 matches the version the repository's other JavaScript package expects.

## Layout

```text
web/
|-- astro.config.mjs          # markdown pipeline, redirects, allowed hosts
|-- src/
|   |-- components/           # header, footer, sidebar, TOC, search, icons
|   |-- config/nav.ts         # sidebar order, reading order, edit links
|   |-- content/docs/         # every documentation page, as Markdown
|   |   |-- get-started/      # overview, why, quickstart, installation
|   |   |-- concepts/         # architecture and the authorization model
|   |   |-- guides/           # task-oriented how-tos
|   |   |-- brokers/          # the shipped brokers and the OpenClaw plugin
|   |   |-- build/            # building a broker on the framework
|   |   |-- deploy/           # host deployment, services, bundles
|   |   |-- operate/          # metrics, state, failure drills
|   |   |-- security/         # security and threat models
|   |   `-- reference/        # CLI, schemas, APIs, configuration
|   |-- content.config.ts     # collection schema for those pages
|   |-- layouts/              # the HTML shell
|   |-- pages/
|   |   |-- index.astro       # landing page
|   |   |-- docs/[...slug].astro
|   |   `-- search.json.ts    # build-time search index
|   `-- styles/               # global.css and landing.css
`-- public/
```

## Adding a page

Create the Markdown file under `src/content/docs/<section>/<name>.md` with `title` and
`description` frontmatter, then add its slug to the matching section in `src/config/nav.ts`. A page
missing from that file still builds, but nothing links to it: the sidebar, breadcrumbs,
previous/next links, and search index all read their order from there.

Callouts use plain HTML, because the Markdown pipeline has no directive plugin:

```html
<div class="callout callout--warn">
<span class="callout__title">Development mode only</span>
<p>Text goes here.</p>
</div>
```

The available modifiers are `callout--note`, `callout--warn`, and `callout--danger`.

## Writing style

Prose here follows the `kill-ai-smell` rules: sentence-case noun-phrase headings, no em dashes, no
labelled-bullet walls, and no contrast rhetoric. Run the checker over anything you add:

```sh
python3 ~/.claude/skills/kill-ai-smell/check.py src/content/docs/<section>/<name>.md
```

The `exactly-three lists` finding fires on the tail of any comma list ending in "and", so a
reference page that enumerates real API fields will trip it. Read the flagged lines before
rewriting them.

## Design tokens

Colours derive from the two values in `assets/logo.svg`: the navy `#0f263d` and the teal `#05b6af`.
Accents are darkened for light mode and lightened for dark mode so text keeps a WCAG AA contrast
ratio. Both themes are defined at the top of `src/styles/global.css`; the theme is chosen from
`prefers-color-scheme` and overridden by an inline script before first paint so a dark-mode reader
never sees a flash.

Surfaces are flat. Sections are separated by a 1px rule and an alternating background tint, and
there are no gradients anywhere in the stylesheets. Landing sections carry exactly one heading:
no eyebrow label above an `h2`.

The vertical rhythm in `.prose` comes from one adjacent-sibling rule. Do not add a
`.prose p { margin: 0 }` style: an element selector outranks `> * + *` and silently collapses every
paragraph gap.

## Deployment

`pnpm build` writes a self-contained static site to `dist/`, which any static host can serve. The
build is not wired into the repository's CI workflow.
