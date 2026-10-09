#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
policy="$root/overrides_central.json"
planner="$root/bin/central-overrides"
owner=rancher
repo_filter=
repo_dir=
dry_run=false
branch_suffix=$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')
branch="central-go-overrides-$branch_suffix"

usage() {
  echo "Usage: $0 [--dry-run] [--repo NAME] [--owner OWNER] [--policy FILE] [--repo-dir DIR]"
}

while (( $# )); do
  case "$1" in
    --dry-run) dry_run=true; shift ;;
    --repo|--owner|--policy|--repo-dir)
      if (( $# < 2 )); then usage >&2; exit 2; fi
      case "$1" in
        --repo) repo_filter=$2 ;;
        --owner) owner=$2 ;;
        --policy) policy=$2 ;;
        --repo-dir) repo_dir=$2 ;;
      esac
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ ! "$owner" =~ ^[a-zA-Z0-9-]+$ ]]; then
  echo "Invalid GitHub owner: $owner" >&2
  exit 2
fi
if [[ -n "$repo_dir" && ( "$dry_run" != true || -z "$repo_filter" ) ]]; then
  echo "--repo-dir requires --dry-run and --repo" >&2
  exit 2
fi

"$root/scripts/build-tools.sh"

repositories=$(jq -er --arg repo "$repo_filter" '
  [.repositories[].name | select($repo == "" or . == $repo)] |
  if length == 0 then error("no configured repositories match --repo") else join("\n") end
' "$policy")

if [[ -z "$repo_dir" ]]; then
  workdir=$(mktemp -d "${TMPDIR:-/tmp}/central-go-overrides.XXXXXXXX")
  trap 'rm -rf -- "$workdir"' EXIT
fi
if [[ "$dry_run" != true ]]; then gh auth setup-git; fi

summarize() {
  printf '%s\n' "$1"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

prune_closed_branches() {
  local repo=$1
  local dir=$2
  local closed_branches open_branches branch
  closed_branches=$(gh pr list --repo "$owner/$repo" --search 'is:closed is:pr head:central-go-overrides-' --json headRefName --jq '.[].headRefName' | sort -u)
  open_branches=$(gh pr list --repo "$owner/$repo" --search 'is:open is:pr head:central-go-overrides-' --json headRefName --jq '.[].headRefName' | sort -u)
  while IFS= read -r branch; do
    [[ -z "$branch" ]] && continue
    if grep -Fxq "$branch" <<< "$open_branches"; then
      continue
    fi
    if git -C "$dir" ls-remote --exit-code --heads origin "refs/heads/$branch" > /dev/null; then
      summarize "Deleting closed central override branch $branch in $owner/$repo."
      git -C "$dir" push origin --delete "$branch"
    fi
  done <<< "$closed_branches"
}

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  printf '## Central Go override results\n' >> "$GITHUB_STEP_SUMMARY"
fi
while IFS= read -r repo; do
  [[ -z "$repo" ]] && continue
  if [[ -n "$repo_dir" ]]; then
    dir=$repo_dir
  else
    dir="$workdir/$repo"
    gh repo clone "$owner/$repo" "$dir" -- --depth=1
  fi
  if [[ "$dry_run" != true ]]; then
    prune_closed_branches "$repo" "$dir"
  fi

  args=(--policy "$policy" --repo "$repo" --repo-dir "$dir")
  if [[ "$dry_run" != true ]]; then args+=(--apply); fi
  result=$("$planner" "${args[@]}")
  summary=$(jq -r '
    "**\(.repository)**: " +
    (if .updates | length > 0 then "updates: " + (.updates | join(", ")) else "no updates" end) +
    (if .held | length > 0 then "; held: " + (.held | join(", ")) else "" end) +
    (if .blocked | length > 0 then "; blocked: " + (.blocked | join(", ")) else "" end)
  ' <<< "$result")
  summarize "$summary"
  if [[ "$dry_run" == true || $(jq '.updates | length' <<< "$result") -eq 0 ]]; then
    continue
  fi

  if [[ -n $(git -C "$dir" ls-remote --heads origin "refs/heads/$branch") ]]; then
    summarize "Branch $branch already exists in $owner/$repo; manual resolution required."
    continue
  fi
  base=$(gh repo view "$owner/$repo" --json defaultBranchRef --jq '.defaultBranchRef.name')
  git -C "$dir" config user.name 'github-actions[bot]'
  git -C "$dir" config user.email '41898282+github-actions[bot]@users.noreply.github.com'
  git -C "$dir" checkout -b "$branch"
  git -C "$dir" add -- go-mod-overrides
  git -C "$dir" commit --no-gpg-sign -m 'Update existing Go module security overrides'
  git -C "$dir" push origin "HEAD:refs/heads/$branch"
  body=$(jq -r --argjson result "$result" '
    .modules as $modules |
    "Update existing go-mod-overrides targets per [rancher/image-build-approver/overrides_central.json](https://github.com/rancher/image-build-approver/blob/main/overrides_central.json).\n\n" +
    ([$result.updates[] | split(": ")[0] as $module |
      "- \(.): \($modules[$module].cves)"] | join("\n")) +
    "\n\nNo new override modules are added. Review build compatibility before merging."
  ' "$policy")
  gh pr create --repo "$owner/$repo" --base "$base" --head "$branch" \
    --title 'Update existing Go module security overrides' \
    --body "$body"
done <<< "$repositories"
