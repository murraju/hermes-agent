# Lantern Integration

Lantern uses Hermes as a sibling agent plane. Hermes owns the agent loop,
sessions, skills, cron-style work, and console protocol. Lantern owns private
data, model routing, provider credentials, policy, redaction, and audit.

The Lantern desktop host launches Hermes with a dedicated `HERMES_HOME` profile
and short-lived bridge credentials. Hermes should only access Lantern media
through the authenticated MCP tool `lantern.search_media`.

Do not add code here that reads Lantern databases, keychain items, raw media
paths, or provider credentials directly.
