---
name: status
description: Show Pharon's status for this repo - last sync, queued uploads and open incidents. Use for /pharon:status.
allowed-tools: Bash(pharon status *)
---

Run `pharon status` (or `"${CLAUDE_PLUGIN_ROOT}/bin/pharon" status` if `pharon` isn't found) and relay it briefly. For each open incident, suggest `/pharon:check-incident <id>`. If the repo isn't linked or the login expired, suggest `/pharon:setup`.
