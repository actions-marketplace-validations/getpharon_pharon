---
name: show
description: Show exactly what Pharon would upload for this repo right now (the inventory, no code and no secret values). Use for /pharon:show or when the user asks what Pharon sends.
allowed-tools: Bash(pharon show *)
---

Run `pharon show` (or `"${CLAUDE_PLUGIN_ROOT}/bin/pharon" show` if `pharon` isn't found) and relay the summary. If the user wants every detail, run `pharon show --json` and point them to the parts they asked about rather than pasting thousands of lines. Remind them that only this inventory leaves the machine.
