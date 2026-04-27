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
