#!/bin/bash
# UserPromptSubmit hook: when a prompt arrives in a session that has sat idle
# for more than STALE_SECONDS, run `git fetch` and tell Claude where the branch
# stands, so work doesn't start from a stale view of the remote.
#
# "Idle" is measured from the previous prompt in the same session. The first
# prompt of a brand-new session is not stale and does not fetch.

STALE_SECONDS=${CLAUDE_FETCH_STALE_SECONDS:-7200}

input=$(cat)
session=$(jq -r '.session_id // empty' <<<"$input" | tr -cd 'A-Za-z0-9_-')
[ -n "$session" ] || exit 0

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
git_dir=$(git rev-parse --absolute-git-dir 2>/dev/null) || exit 0

# Stamps live inside .git so they are per-clone, never committed, and survive
# a resumed session (same session id, new process).
stamp_dir="$git_dir/claude-prompt-stamps"
stamp="$stamp_dir/$session"
now=$(date +%s)
last=$(cat "$stamp" 2>/dev/null)
mkdir -p "$stamp_dir" && echo "$now" > "$stamp"
find "$stamp_dir" -type f -mtime +30 -delete 2>/dev/null

case "$last" in ''|*[!0-9]*) exit 0 ;; esac
idle=$(( now - last ))
[ "$idle" -gt "$STALE_SECONDS" ] || exit 0

idle_text="$(( idle / 3600 ))h $(( idle % 3600 / 60 ))m"

if fetch_err=$(git fetch --quiet 2>&1); then
  branch=$(git symbolic-ref --quiet --short HEAD || echo "detached HEAD")
  if counts=$(git rev-list --left-right --count 'HEAD...@{upstream}' 2>/dev/null); then
    read -r ahead behind <<<"$counts"
    upstream=$(git rev-parse --abbrev-ref '@{upstream}')
    state="$branch is $behind behind and $ahead ahead of $upstream"
    [ "$behind" -gt 0 ] && state+=" — the local branch is out of date; bring it up to date (or tell the user) before building on it"
  else
    state="$branch has no upstream to compare against"
  fi
  msg="This session was idle for $idle_text, so \`git fetch\` was run automatically. $state."
else
  msg="This session was idle for $idle_text, but the automatic \`git fetch\` failed: $fetch_err. The view of the remote may be stale."
fi

jq -n --arg msg "$msg" \
  '{hookSpecificOutput: {hookEventName: "UserPromptSubmit", additionalContext: $msg}}'
