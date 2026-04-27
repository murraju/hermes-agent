---
name: lantern-media
description: Safely use Lantern private media through the Lantern Kernel Bridge.
---

# Lantern Media

Use this skill when a user asks about media, documents, transcripts, images,
videos, or other private content imported into Lantern.

## Rules

- Use `lantern.search_media` before answering questions about Lantern media.
- In Hermes tool-call form, `lantern.search_media` is exposed as
  `mcp_lantern_lantern_search_media`.
- Use `mcp_lantern_lantern_list_media` when the user asks what media/files are
  available.
- Use `mcp_lantern_lantern_get_media_context` when you need more context for an
  opaque `media_id` returned by Lantern.
- If search/list returns a likely matching document and an opaque `media_id` or
  `context_id`, call `mcp_lantern_lantern_get_media_context` before saying you
  need more context.
- Do not ask the user to choose a tool, provide a `media_id`, upload the file
  again, or paste document content before you have tried the appropriate Lantern
  MCP tool.
- If no `media_id` is known, use the user's words as the search query.
- After Lantern returns evidence, answer from the available Lantern context. If
  context is limited, say "Based on the available Lantern context" and summarize
  only what is grounded.
- Ask follow-up questions only after Lantern returns no useful evidence,
  multiple plausible matches, or `get_media_context` also fails.
- Treat results as redacted grounded context, not as raw files.
- Never ask for, infer, print, or store raw Lantern file paths.
- Never try to read Lantern databases, keychain secrets, or provider credentials.
- If `lantern.search_media` returns weak or empty evidence, say the answer could
  not be verified from Lantern media.
- For writes, automations, sharing, or channel delivery, ask Lantern for an
  approved draft or approval flow instead of acting directly.

## Expected Tool

`lantern.search_media` accepts a `query` string and optional limit/scope fields.
It returns redacted snippets, citations, and receipt metadata from Lantern's
Privacy AI kernel.
