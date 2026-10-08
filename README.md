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