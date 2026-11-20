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

Before any of these rules are checked, a PR is skipped if any of the following is true:

- It has a `hold`, `do-not-merge`, or `do-not-merge/*` label.
- Any commit is not authored by `renovate-rancher[bot]`, or is committed by someone other than `renovate-rancher[bot]` or `web-flow` (GitHub's committer for commits created through the API).
- A non-bot user has left an inline review comment, a PR comment, or a review that is not an approval.

A PR is also skipped whenever any of these checks can't be completed because a GitHub API call failed.