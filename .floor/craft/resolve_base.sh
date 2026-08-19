#!/bin/sh
# Resolve BASE for craft jobs. Sourced from floor.yml.
# PR: pull_request.base.sha. Push: github.event.before.
# Never the root commit. Empty range (BASE == HEAD) exits 3.
# schedule / workflow_dispatch must not source this — those jobs are skipped.

ZERO=0000000000000000000000000000000000000000
if [ "$EVENT_NAME" = "pull_request" ] && [ -n "$PR_BASE" ]; then
  BASE="$PR_BASE"
elif [ "$EVENT_NAME" = "push" ] && [ -n "$PUSH_BEFORE" ] && [ "$PUSH_BEFORE" != "$ZERO" ]; then
  BASE="$PUSH_BEFORE"
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
