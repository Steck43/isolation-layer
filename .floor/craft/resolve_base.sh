#!/bin/sh
# Resolve BASE for craft jobs. Sourced from floor.yml.
# PR: pull_request.base.sha.
# Push: github.event.before, unless that is the all-zero new-branch sentinel,
# in which case compare against the origin default. Earned 2026-08-19: four
# public README PRs went BLOCKED because required craft jobs on the first
# push of a new branch saw PUSH_BEFORE=0000… and exited 3.
# Never the root commit. Empty range (BASE == HEAD) exits 3.
# schedule / workflow_dispatch must not source this — those jobs are skipped.

ZERO=0000000000000000000000000000000000000000

_default_base() {
  if git rev-parse --verify origin/HEAD >/dev/null 2>&1; then
    git rev-parse origin/HEAD
    return 0
  fi
  for ref in origin/main origin/master origin/scaffold; do
    if git rev-parse --verify "$ref" >/dev/null 2>&1; then
      git rev-parse "$ref"
      return 0
    fi
  done
  return 1
}

if [ "$EVENT_NAME" = "pull_request" ] && [ -n "$PR_BASE" ]; then
  BASE="$PR_BASE"
elif [ "$EVENT_NAME" = "push" ] && [ -n "$PUSH_BEFORE" ] && [ "$PUSH_BEFORE" != "$ZERO" ]; then
  BASE="$PUSH_BEFORE"
elif [ "$EVENT_NAME" = "push" ] && [ "$PUSH_BEFORE" = "$ZERO" ]; then
  if ! BASE="$(_default_base)"; then
    echo "::error::first push of a new branch and no origin default"
    exit 3
  fi
else
  echo "::error::cannot determine BASE event=$EVENT_NAME (craft is PR/push only)"
  exit 3
fi
if ! git rev-parse --verify "$BASE" >/dev/null 2>&1; then
  echo "::error::BASE does not resolve: $BASE"
  exit 3
fi
if [ "$(git rev-parse "$BASE")" = "$(git rev-parse HEAD)" ]; then
  echo "::error::empty range BASE==HEAD; craft would inspect nothing"
  exit 3
fi
echo "BASE=$BASE HEAD=$(git rev-parse HEAD)"
