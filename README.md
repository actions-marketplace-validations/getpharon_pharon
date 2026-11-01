# Pharon

**The warning light for your stack.** [Pharon](https://getpharon.com) keeps an inventory of every package, container image, GitHub Action, runtime and cloud service you run, and alerts you within minutes when a compromised release, an exploited vulnerability, a vendor breach or an end-of-life deadline reaches it. Scans run on your machine; your code never leaves it.

This repository holds the parts that run on your side: the Claude Code plugin, the zero-dependency `pharon` CLI it uses, and the GitHub Action. You need a Pharon account ([sign up](https://getpharon.com/signup)), [Claude Code](https://code.claude.com) and Node.js 18 or later.

## Install the Claude Code plugin

```
/plugin marketplace add getpharon/pharon
/plugin install pharon@pharon
```

Then open Claude Code in a repository and run `/pharon:setup`. It logs you in, links the repo, scans the stack locally and shows exactly what will be uploaded before anything is sent.

| In Claude Code | What it does |
| --- | --- |
| `/pharon:setup` | Connect a repo, or review and repair its setup |
| `/pharon:status` | Last sync and open incidents for this repo |
| `/pharon:show` | Exactly what is uploaded for this repo |
| `/pharon:check-incident <id>` | Check whether this machine was affected, and which secrets to rotate |

Full guide: [getpharon.com/docs](https://getpharon.com/docs).

## GitHub Action

Keeps the inventory current from CI and checks pull requests for components with an open incident. Create a CI token on the project page in Pharon, store it as the secret `PHARON_TOKEN`, and add:

```yaml
on: { push: { branches: [main] }, pull_request: {}, schedule: [{ cron: "17 3 * * *" }] }
jobs:
  pharon:
    runs-on: ubuntu-latest
    permissions: { contents: read, pull-requests: write }
    steps:
      - uses: actions/checkout@<sha>
      - uses: getpharon/pharon@<sha>
        with: { token: "${{ secrets.PHARON_TOKEN }}", fail-on: high }
```

## What leaves your machine

Only an inventory: component names, versions and the paths of stack files. Source code, file contents and secret values never do, and `/pharon:show` prints the exact upload. Redaction rules can drop or hash internal names first. Every incident notice is signed with Ed25519; the CLI rejects unsigned or tampered notices and never runs anything from one. Details: [what we see](https://getpharon.com/what-we-see).

## Links

- [Security notices](https://getpharon.com/notices): compromised packages, exploited vulnerabilities, vendor breaches and end-of-life deadlines
- [Pricing](https://getpharon.com/pricing)
- Support: support@gitmore.io

Pharon is part of [Gitmore](https://gitmore.io). The code in this repository is licensed under the [Apache License 2.0](LICENSE).
