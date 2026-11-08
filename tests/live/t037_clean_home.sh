#!/usr/bin/env bash
# T-037 live run (design cases 27 and 28). Not part of `make test`: it needs the network, the
# `claude` CLI and a real API key for one Haiku call.
#
#   python3 <kit>/with-secret.py <key file>=ANTHROPIC_API_KEY -- bash tests/live/t037_clean_home.sh <branch>
#   python3 <kit>/with-secret.py openrouter.env=SIGNIN_ENV -- bash tests/live/t037_clean_home.sh <branch>
#
# The second form takes a sign-in file that holds `export ANTHROPIC_BASE_URL=... ANTHROPIC_AUTH_TOKEN=...
# ANTHROPIC_API_KEY=...` lines (with-secret.py puts its text in SIGNIN_ENV). The three values go to the
# one `claude -p` call only and are scrubbed from the evidence file.
#
# <branch> is a branch of github.com/jdgafx/agent-guardrails that holds version 0.2.0. A throwaway
# HOME, an empty cwd and `env -i` mean no clone, no PYTHONPATH and no sign-in is reachable. The
# first install is the README's two commands on `main` (0.1.0, before 0.2.0 is merged); then the
# marketplace moves to <branch>. After the merge, main is 0.2.0 and step 2 has nothing to move.
set -u
BRANCH=${1:?usage: t037_clean_home.sh <branch> [evidence file]}
EVIDENCE=${2:-/home/chris2/factory-hq/evidence/agent-guardrails-T-037/live-run.txt}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
if [ -n "${SIGNIN_ENV:-}" ]; then eval "$SIGNIN_ENV"; unset SIGNIN_ENV; fi
API_KEY=${ANTHROPIC_API_KEY:-}
AUTH_TOKEN=${ANTHROPIC_AUTH_TOKEN:-}
BASE_URL=${ANTHROPIC_BASE_URL:-}
[ -n "$API_KEY$AUTH_TOKEN" ] || { echo "run through with-secret.py" >&2; exit 2; }
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL
CLAUDE_DIR=$(dirname "$(command -v claude)")
T=$(mktemp -d)
mkdir -p "$T/home" "$T/empty"
LOG=$T/log
FAILED=0
trap 'rm -rf "$T"' EXIT

say() { echo "$*" | tee -a "$LOG"; }
check() { if "$@" >>"$LOG" 2>&1; then say "ok:   $*"; else say "FAIL: $*"; FAILED=1; fi; }
clean() { (cd "$T/empty" && env -i PATH="/usr/bin:/bin:$CLAUDE_DIR" HOME="$T/home" "$@"); }
CACHE=$T/home/.claude/plugins/cache/agent-guardrails/agent-guardrails
RECORD=$T/home/.claude/plugins/installed_plugins.json
named() { python3 -c 'import json,sys; r=json.load(open(sys.argv[1]))["plugins"]["agent-guardrails@agent-guardrails"]; print(r[0]["installPath"])' "$RECORD"; }
sha() { python3 -c 'import json,sys; r=json.load(open(sys.argv[1]))["plugins"]["agent-guardrails@agent-guardrails"]; print(r[0]["gitCommitSha"])' "$RECORD"; }

say "== claude $(clean claude --version 2>&1) on $(uname -sr), python3 $(python3 --version 2>&1)"
say "== 1. README install commands, main"
clean claude plugin marketplace add jdgafx/agent-guardrails >>"$LOG" 2>&1
clean claude plugin install agent-guardrails@agent-guardrails >>"$LOG" 2>&1
check test -d "$CACHE/0.1.0"
say "record names: $(named)  commit: $(sha)"
FIRST=$(sha)

say "== 2. move the marketplace to $BRANCH"
MOVED=none
clean claude plugin marketplace add "jdgafx/agent-guardrails#$BRANCH" >>"$LOG" 2>&1 && MOVED=add-with-ref
if [ "$MOVED" = none ]; then
  clean claude plugin marketplace remove agent-guardrails >>"$LOG" 2>&1
  clean claude plugin marketplace add "jdgafx/agent-guardrails#$BRANCH" >>"$LOG" 2>&1 && MOVED=remove-then-add
fi
clean claude plugin marketplace update agent-guardrails >>"$LOG" 2>&1
clean claude plugin install agent-guardrails@agent-guardrails >>"$LOG" 2>&1
clean claude plugin update agent-guardrails@agent-guardrails >>"$LOG" 2>&1
say "moved by: $MOVED; record names: $(named)  commit: $(sha)"
check test "$(sha)" != "$FIRST"
check test -d "$CACHE/0.1.0"
check test -d "$CACHE/0.2.0"
check test "$(named)" = "$CACHE/0.2.0"

say "== 3. one real claude -p session, one ls call"
OUT=$T/session.json
(cd "$T/empty" && env -i PATH="/usr/bin:/bin:$CLAUDE_DIR" HOME="$T/home" bash -c \
  'read -r ANTHROPIC_API_KEY <&3; read -r ANTHROPIC_AUTH_TOKEN <&3; read -r ANTHROPIC_BASE_URL <&3
   export ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL
   for v in ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL; do [ -n "${!v}" ] || unset $v; done
   exec claude -p "Run the shell command ls and nothing else." --allowedTools "Bash(ls)" --output-format json --model haiku' \
  3<<<"$API_KEY"$'\n'"$AUTH_TOKEN"$'\n'"$BASE_URL" >"$OUT" 2>>"$LOG")
SESSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["session_id"])' "$OUT" 2>>"$LOG")
say "session_id: $SESSION"
check test -n "$SESSION"
check test -d "$T/home/.claude/plugins/data/agent-guardrails-agent-guardrails/audit"

say "== 4. the README start command, from an empty cwd, nothing else installed"
START=$(grep -m1 '^(for f in ' "$REPO/README.md")
START=${START/exec python3 \"\$f\"/exec python3 \"\$f\" --port 0}
DASH=$T/dash.out
: >"$DASH"
clean bash -c "$START" >"$DASH" 2>&1 &
JOB=$!
exec 9<>"$T/wait.fifo" 2>/dev/null || { mkfifo "$T/wait.fifo"; exec 9<>"$T/wait.fifo"; }
for _ in $(seq 1 80); do grep -q "Ctrl-C stops it" "$DASH" && break; read -r -t 0.25 -u 9 _ || true; done
cat "$DASH" >>"$LOG"
LINK=$(grep -o 'http://127.0.0.1:[0-9]*/?key=[^ ]*' "$DASH" | head -1)
check test -n "$LINK"
PORT=$(echo "$LINK" | sed 's|http://127.0.0.1:\([0-9]*\)/.*|\1|')
DKEY=${LINK##*key=}
EVENTS=$T/events.json
curl -s "http://127.0.0.1:$PORT/api/events?after=&key=$DKEY" >"$EVENTS"
curl -s "http://127.0.0.1:$PORT/api/policy?key=$DKEY" >"$T/policy.json"
pkill -INT -f "$T/home/.claude/plugins/cache" 2>/dev/null
wait "$JOB" 2>/dev/null

say "== 5. case 27: what the dashboard showed"
check python3 -c 'import json,sys; ev=json.load(open(sys.argv[1])); n=[e for e in ev if e.get("session_id")==sys.argv[2]]; print(len(n), "rows of the session"); sys.exit(0 if n else 1)' "$EVENTS" "$SESSION"
check grep -F "  plugin: $CACHE/0.2.0 (version 0.2.0" "$DASH"
check grep -F "  shipped policy: $CACHE/0.2.0/policy.json" "$DASH"
check grep -E "^  data folder: $T/home/.claude/plugins/data/agent-guardrails-agent-guardrails " "$DASH"
check python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); sys.exit(0 if p.get("rules") else 1)' "$T/policy.json"

say "== 6. case 28: the saved evidence holds neither key"
mkdir -p "$(dirname "$EVIDENCE")"
cp "$LOG" "$EVIDENCE.tmp"
AK=$API_KEY TK=$AUTH_TOKEN DK=$DKEY T=$T python3 - "$EVIDENCE.tmp" "$EVIDENCE" <<'PY'
import os, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
for var, mark in (("AK", "[REDACTED]"), ("TK", "[REDACTED]"), ("DK", "[REDACTED]")):
    if os.environ.get(var):
        text = text.replace(os.environ[var], mark)
text = text.replace(os.environ["T"], "$T")
open(sys.argv[2], "w", encoding="utf-8").write(text)
os.remove(sys.argv[1])
PY
if grep -qF -e "${API_KEY:-no-key}" -e "${AUTH_TOKEN:-no-token}" -e "${DKEY:-no-dkey}" "$EVIDENCE"; then say "FAIL: a key is in the evidence file"; FAILED=1; else say "ok:   no key in $EVIDENCE"; fi
echo "RESULT: $([ $FAILED = 0 ] && echo PASS || echo FAIL)" | tee -a "$EVIDENCE"
exit $FAILED
