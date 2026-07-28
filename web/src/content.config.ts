import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

const docs = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/docs" }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    // Overrides the sidebar entry text when the full title is too long.
    navLabel: z.string().optional(),
  }),
});

export const collections = { docs };
