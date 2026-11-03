#!/usr/bin/env bash
# Builds dist/pharon-openai-<version>.zip, the skills-only package for OpenAI's plugin directory (platform.openai.com/plugins).
# The directory rejects lifecycle hooks, so hooks/ stays out and the skills lose their Claude Code-only parts.
set -euo pipefail
cd "$(dirname "$0")/.."
src=pharon-plugin
version=$(node -p 'require("./pharon-plugin/.claude-plugin/plugin.json").version')
test "$(node -p 'require("./openai/plugin.json").version')" = "$version" || { echo "openai/plugin.json version must be $version" >&2; exit 1; }
if grep -E '"(feed|root)-dev"' "$src/lib/keys.mjs"; then echo "pharon-plugin/lib/keys.mjs still trusts development keys" >&2; exit 1; fi

out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
mkdir -p "$out/assets" "$out/lib" dist
cp openai/plugin.json LICENSE "$out/"
cp "$src/.claude-plugin/icon.png" "$out/assets/"
cp -R "$src/bin" "$src/skills" "$out/"
for f in "$src"/lib/*.mjs; do case "$f" in *.test.mjs|*/keys.local.mjs) ;; *) cp "$f" "$out/lib/" ;; esac; done

perl -pi -e '
  s/^(argument-hint|allowed-tools):.*\n//;
  s/"\$\{CLAUDE_PLUGIN_ROOT\}\/bin\/pharon"/node "<this skill folder>\/..\/..\/bin\/pharon"/g;
  s/^Incident ID: `\$ARGUMENTS`/Incident ID: the one the user gave. Ask for it if they gave none./;
  s/\$ARGUMENTS/<id>/g;
  s/ with (the )?AskUserQuestion( tool)?//g; s/AskUserQuestion/question/g;
  s/the inventory refreshes automatically whenever a Claude Code session starts or ends and the stack files changed/the inventory does not refresh on its own in Codex, so run this setup again after the stack changes, or add the Pharon GitHub Action (getpharon.com\/docs) to keep it current from CI/;
' "$out"/skills/*/SKILL.md
# A rewrite that stopped matching leaves the Claude Code text behind: refuse to ship it.
if grep -rnE 'CLAUDE_PLUGIN_ROOT|\$ARGUMENTS|AskUserQuestion|Claude Code session|^(argument-hint|allowed-tools):' "$out/skills"; then
  echo "Claude Code-only text left in the skills (above): update the rewrites in openai/build.sh" >&2; exit 1
fi

zip="$PWD/dist/pharon-openai-$version.zip"
rm -f "$zip"
(cd "$out" && zip -qrX "$zip" .)
echo "$zip"
