// @ts-check
import { defineConfig, passthroughImageService } from "astro/config";
import rehypeSlug from "rehype-slug";
import rehypeAutolinkHeadings from "rehype-autolink-headings";

export default defineConfig({
  site: "https://brokerkit.dev",
  trailingSlash: "ignore",
  // The site ships only SVG, so the native sharp pipeline is not installed.
  image: { service: passthroughImageService() },
  redirects: {
    "/docs": "/docs/get-started/overview",
  },
  markdown: {
    shikiConfig: {
      themes: { light: "github-light", dark: "github-dark" },
      wrap: false,
    },
    rehypePlugins: [
      rehypeSlug,
      [
        rehypeAutolinkHeadings,
        {
          behavior: "append",
          properties: { class: "heading-anchor", ariaHidden: "true", tabIndex: -1 },
          content: { type: "text", value: "#" },
        },
      ],
    ],
  },
  devToolbar: { enabled: false },
  // The dev and preview servers reject unknown Host headers, which blocks
  // previewing over a tailnet by MagicDNS name. A leading dot allows the
  // whole suffix. Both servers read this one setting.
  server: { allowedHosts: [".ts.net"] },
});
