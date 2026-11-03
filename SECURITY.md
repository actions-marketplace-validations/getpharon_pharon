# Security policy

## Reporting a vulnerability

Please report security issues privately by email to support@gitmore.io, with "Security" in the subject line. Don't open a public issue. Say what is affected (the `pharon` CLI, the Claude Code plugin, the GitHub Action or getpharon.com), how to reproduce it and the impact you see. We'll confirm we received it and keep you updated until it is fixed.

## Supported versions

Fixes go into the latest release and `main`.

## How Pharon protects you

- Only an inventory leaves your machine: component names, versions and the paths of stack files. Source code, file contents and secret values never do, and `pharon show` prints the exact upload.
- The plugin's hooks do nothing until you have linked the repo and approved the first upload in `/pharon:setup`.
- Incident notices are signed with Ed25519. The CLI rejects unsigned or tampered notices and never runs anything taken from one.
- Cloud scanning is opt-in and runs your own `aws`, `gcloud` or `az` CLI with an allowlist of read-only describe and list calls.
- Releases are built in GitHub Actions with SHA-256 checksums and a build provenance attestation.

More detail: [what we see](https://getpharon.com/what-we-see) and the [privacy policy](https://getpharon.com/privacy).
