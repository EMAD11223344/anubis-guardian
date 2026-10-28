# Security Policy

## Reporting a vulnerability in Anubis Guardian itself

Report privately via [GitHub Security Advisories](https://github.com/EMAD11223344/anubis-guardian/security/advisories/new) — **not** a public issue. Include the version (`anubis-guardian --version` or `package.json`), the affected command/flag, and a minimal reproduction. You will get an acknowledgement and a fix/assessment; credit is given if desired.

## In scope

- The scanner itself: CLI, engine, report rendering, URL mode, adapters, hook, and anything executed on the maintainer's or user's machine.
- Violations of the tool's own contracts (e.g. a path where a raw secret value reaches an output artifact, scanned code being executed, a write into the scanned tree, a network call outside the consent-gated modes).

## Out of scope

- Findings that Anubis Guardian reports **about scanned code**. Run the scanner on your own repository and read the report — that is the product working as intended, not a tool vulnerability.
- Reports about repositories or systems you do not own.

## Supported versions

The latest published npm release receives security fixes. Intermediate main-branch states may exist between releases (fix rounds are built and reviewed before the owner tags a release) — those are not supported install targets; install from npm or a tagged commit.
