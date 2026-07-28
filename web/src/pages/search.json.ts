import type { APIRoute } from "astro";
import { getCollection } from "astro:content";
import { readingOrder } from "../config/nav";

/**
 * Search index consumed by the client-side dialog. Markdown is reduced to plain
 * text so the browser can substring-match without a search library. Original
 * casing is preserved because the same string is shown as the result excerpt;
 * the client lowercases a copy for matching.
 */
function toPlainText(markdown: string): string {
  return markdown
    .replace(/```[\s\S]*?```/g, " ")
    // Keep inline-code contents: they carry the identifiers readers search for,
    // and dropping them leaves gaps like "beneath , , and ." in excerpts.
    .replace(/`([^`]*)`/g, "$1")
    .replace(/<[^>]+>/g, " ")
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/^[#>\-*|:]+/gm, " ")
    // Table cell separators and row rules would otherwise show up in excerpts.
    .replace(/\|/g, " ")
    .replace(/^\s*[-:\s]+$/gm, " ")
    // Underscores are left alone: snake_case identifiers such as
    // matched_rule_ids are exactly what readers search for.
    .replace(/[*~]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

export const GET: APIRoute = async () => {
  const docs = await getCollection("docs");
  const order = new Map(readingOrder.map((entry, position) => [entry.slug, position]));

  const index = docs
    .filter((doc) => order.has(doc.id))
    .sort((a, b) => (order.get(a.id) ?? 0) - (order.get(b.id) ?? 0))
    .map((doc) => ({
      slug: doc.id,
      title: doc.data.title,
      section: readingOrder.find((entry) => entry.slug === doc.id)?.section ?? "Documentation",
      description: doc.data.description,
      body: toPlainText(doc.body ?? "").slice(0, 9000),
    }));

  return new Response(JSON.stringify(index), {
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
};
