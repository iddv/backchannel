#!/bin/sh
# Put two other vendors' coding agents on a private backchannel and let them use it for real:
# Codex hosts, Gemini (the Antigravity CLI, `agy`) joins as a client. Everything is loopback-only on its own
# port with its own data, so your real backchannel is untouched.
#
#   scripts/agents/run.sh [minutes] [brief-directory] [output-directory]
#
# A brief directory holds common.md, codex.md and gemini.md (see scripts/agents/discussion/). In the briefs,
# {INVITE} becomes the host's invite code, {REPO} this repository, {END} the time the session should wrap up.
# Reports land in the output directory: codex-report.md, gemini-report.md and messages.txt (what the host
# stored: ciphertext only).
#
# Codex gets the server as a per-run override. agy only reads MCP servers from its global config, so an entry
# named backchannel-test is added for the run and removed again when it ends.
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
MINUTES=${1:-15}
BRIEF=${2:-$REPO/scripts/agents/discussion}
OUT=${3:-$(mktemp -d -t backchannel-agents-XXXXXX)}
mkdir -p "$OUT"
BRIEF=$(cd "$BRIEF" && pwd) # the agents are started from other directories
OUT=$(cd "$OUT" && pwd)
PORT=${BC_AGENT_PORT:-18990}
PY=$REPO/.venv/bin/python
[ -x "$PY" ] || (cd "$REPO" && uv sync --locked -q)
mkdir -p "$OUT/codex" "$OUT/gemini" "$OUT/codex-data" "$OUT/gemini-data"

env_for() { echo "BACKCHANNEL_ROLE=$1 BACKCHANNEL_NAME=$2 BACKCHANNEL_PORT=$PORT BACKCHANNEL_BIND=127.0.0.1 BACKCHANNEL_DATA=$OUT/$2-data"; }
[ -s "$BRIEF/common.md" ] && [ -s "$BRIEF/codex.md" ] && [ -s "$BRIEF/gemini.md" ] || { echo "no briefs in $BRIEF" >&2; exit 1; }
FP=$(env $(env_for host codex) "$PY" -m backchannel status | sed -n 's/.*key \([A-Z2-7-]*\),.*/\1/p')
END=$(date -d "+$MINUTES minutes" +%H:%M)
brief() {
    cat "$BRIEF/common.md" "$BRIEF/$1.md" |
        sed "s|{INVITE}|bc1:127.0.0.1:$PORT:$FP|g; s|{REPO}|$REPO|g; s|{END}|$END|g; s|{MINUTES}|$MINUTES|g"
}
LIMIT=$((MINUTES * 60 + 240)) # time to write the report after the discussion ends

agy mcp add -e BACKCHANNEL_ROLE=client -e BACKCHANNEL_NAME=gemini -e "BACKCHANNEL_PORT=$PORT" \
    -e BACKCHANNEL_BIND=127.0.0.1 -e "BACKCHANNEL_DATA=$OUT/gemini-data" backchannel-test "$PY" -- -m backchannel >/dev/null
trap 'agy mcp remove backchannel-test >/dev/null 2>&1 || true' EXIT INT TERM

(cd "$OUT/codex" && timeout "$LIMIT" codex exec --skip-git-repo-check -s read-only -C "$REPO" \
    -c "mcp_servers.backchannel.command=\"$PY\"" -c 'mcp_servers.backchannel.args=["-m","backchannel"]' \
    -c "mcp_servers.backchannel.env={BACKCHANNEL_ROLE=\"host\",BACKCHANNEL_NAME=\"codex\",BACKCHANNEL_PORT=\"$PORT\",BACKCHANNEL_BIND=\"127.0.0.1\",BACKCHANNEL_DATA=\"$OUT/codex-data\"}" \
    -o "$OUT/codex-report.md" "$(brief codex)" </dev/null >"$OUT/codex.log" 2>&1) &
sleep 20 # the host has to be listening before the client looks for it
(cd "$OUT/gemini" && timeout "$LIMIT" agy --add-dir "$REPO" --settings '{"permissions":{"allow":["mcp(backchannel-test/*)"]}}' \
    -p "$(brief gemini)" </dev/null >"$OUT/gemini-report.md" 2>"$OUT/gemini.err") || true
wait
sqlite3 "$OUT/codex-data/backchannel.db" \
    "select id, datetime(ts,'unixepoch','localtime'), sender, recipient, length(body), substr(body,1,5) from messages" \
    >"$OUT/messages.txt" 2>/dev/null || true
echo "reports in $OUT"
