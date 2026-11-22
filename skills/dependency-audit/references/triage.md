# Triage: does this advisory matter here?

Audit tools match package versions against advisories. They do not know how you use the
package. Use these questions to move an item up or down - and write the reason down.

## Raise priority

- Internet-facing service and the vulnerable function processes request data
  (parsers, template engines, URL/HTML sanitizers, image/XML/YAML loaders, auth libraries).
- Known exploited: listed in CISA KEV, or a high EPSS score (https://www.first.org/epss/).
- Remote code execution, auth bypass, SSRF, SQL injection, path traversal, prototype pollution
  reaching `merge`/`set` on request bodies.
- The package runs with secrets available (CI, build scripts, `postinstall`).

## Lower priority (still track)

- Dev/build-only dependency that never runs in production and never sees untrusted input
  (linters, test runners) - but keep CI-secret exposure in mind.
- ReDoS in a function only called with constant input.
- Advisory concerns a platform or feature you do not use (Windows-only path handling, an
  optional adapter you have not configured).

## Transitive dependencies

1. Find who pulls it in: `npm explain pkg` / `npm ls pkg`, `pipdeptree -r -p pkg`,
   `composer why vendor/pkg`.
2. Prefer upgrading the parent. npm's `fixAvailable` names the package and version to install.
3. If the parent has no fixed release, pin the child (npm `overrides`, pip constraints file,
   Composer `conflict` or an explicit require) and run tests.

## No fix available

- Mitigate: disable the feature, validate input before it reaches the library, upgrade the
  runtime, add a WAF rule as a temporary measure.
- Replace: a maintained alternative with similar API.
- Accept: record the advisory ID, why it is not exploitable here, who accepted it and a review
  date (30-90 days). Do not suppress without a reason.

## Semver-major fixes

Read the changelog/migration guide, upgrade in a separate pull request, run the full test suite
and a smoke test of the affected feature. Never use `npm audit fix --force` blindly: it can
downgrade or jump majors across many packages at once.
