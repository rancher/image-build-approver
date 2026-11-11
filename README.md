# image-build-approver

This repository contains a GitHub Action that processes `image-build-XXXX` repositories and approves PRs authored by the renovate-rancher bot.

Each configured repository is evaluated for PRs that change an `ARG GO_IMAGE=...` line. Add repositories, extra changed-line regular expressions, and allowed files to `config.json`:

```json
{
  "repositories": [
    {
      "name": "image-build-example",
      "regexes": ["^ARG ALPINE_VERSION=", "^ARG SOME_OTHER_IMAGE="],
      "files": ["TAG"]
    }
  ]
}
```

The `regexes` and `files` keys are optional. Every regular expression is matched against added and removed lines in the PR diff, after the diff prefix (`+` or `-`) is removed. All configured repositories receive the `ARG GO_IMAGE=...` check.

The `files` list contains exact repository-relative paths. A PR qualifies under this rule only if it changes at least one file and all changed files are in the list.