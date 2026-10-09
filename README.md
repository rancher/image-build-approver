# image-build-approver

This repository contains a GitHub Action that processes `image-build-XXXX` repositories and approves PRs authored by the renovate-rancher bot.

Each configured repository is evaluated for PRs that change the root-level `TAG` file or an `ARG GO_IMAGE=...` line. Add repositories and any extra changed-line regular expressions to `config.json`:

```json
{
  "repositories": [
    {
      "name": "image-build-example",
      "regexes": ["^ARG ALPINE_VERSION=", "^ARG SOME_OTHER_IMAGE="]
    }
  ]
}
```

The `regexes` key is optional. Every regular expression is matched against added and removed lines in the PR diff, after the diff prefix (`+` or `-`) is removed. All configured repositories receive the root-level `TAG` and `ARG GO_IMAGE=...` checks.

## Central Go overrides

`overrides_central.json` defines targets, CVEs, minimum Go versions, and
per-repo holds. The workflow updates existing `go-mod-overrides` directives,
adds CVE comments, and reports Dockerfile Go incompatibilities.
It defaults to dry run and never auto-approves PRs. Run
`scripts/generate_pr.sh --dry-run [--repo NAME]` to preview all or one;
omit `--dry-run` to open PRs.

The planner is a Go binary. Run `scripts/build-tools.sh` to build
`bin/central-overrides` locally; `scripts/generate_pr.sh` builds it before use.
