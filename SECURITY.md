# Security Policy

## Supported Versions

This project is in early development. Only the latest release on the `main` branch is supported.

| Version | Supported |
|---------|-----------|
| latest  | yes       |
| older   | no        |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Use GitHub's private vulnerability reporting instead:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Fill in the form with as much detail as possible: affected versions, reproduction steps, and the observed impact.

You should expect an initial response within **7 days**. If the report is accepted, a fix and a coordinated disclosure timeline will be discussed in the private advisory thread.

## Scope

In scope:

- Issues in the `splunk-cloud-cli` binary that lead to credential leakage, command injection, request smuggling, or unsafe TLS behavior.
- Issues in the build / release pipeline that could allow tampering with distributed artifacts.

Out of scope:

- Vulnerabilities in Splunk Cloud Platform itself (report those to Splunk).
- Misconfiguration of the user's own Splunk stack, OS, or shell environment.
- Dependency vulnerabilities that only affect `dev-dependencies` and cannot be triggered through normal CLI usage.

## Supply Chain Protections

This project applies common OSS supply-chain hardening practices:

- `Cargo.lock` is committed and CI builds with `--locked`.
- GitHub Actions are pinned by commit SHA.
- Release artifacts are built on GitHub-hosted runners and published with build provenance attestations (`actions/attest-build-provenance`).
- `cargo audit` runs on every CI build to detect known advisories in dependencies.
- Dependabot watches both `cargo` and `github-actions` ecosystems with a cooldown window to avoid freshly published malicious versions.
