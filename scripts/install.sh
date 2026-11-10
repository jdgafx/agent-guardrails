#!/bin/sh
# One command installs agent-guardrails: the guard into Claude Code, and the word `guardrails`
# that opens the dashboard.
#
#   curl -fsSL https://raw.githubusercontent.com/jdgafx/agent-guardrails/main/scripts/install.sh | sh
#
# Run it again to update. It needs python3, and git or curl+tar. It installs nothing else, asks for
# no password and no account. Plain sh, so it runs on macOS and Linux alike.
set -eu

REPO="jdgafx/agent-guardrails"
SRC="${XDG_DATA_HOME:-$HOME/.local/share}/agent-guardrails"
BIN="$HOME/.local/bin"
say() { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

have python3 || { say "agent-guardrails needs python3 on PATH. Install Python 3.9 or newer, then run this again."; exit 1; }

# Run from a clone: install that clone. Piped from curl: fetch a copy, or update the one that is there.
here=$(cd "$(dirname "$0")/.." 2>/dev/null && pwd || true)
if [ -n "$here" ] && [ -f "$here/packages/guardrails-plugin/policy.json" ]; then
  SRC="$here"
elif [ -d "$SRC/.git" ] && have git; then
  git -C "$SRC" pull -q --ff-only
elif have git; then
  rm -rf "$SRC"
  mkdir -p "$(dirname "$SRC")"
  git clone -q --depth 1 "https://github.com/$REPO.git" "$SRC"
elif have curl && have tar; then
  rm -rf "$SRC"
  mkdir -p "$SRC"
  curl -fsSL "https://github.com/$REPO/archive/refs/heads/main.tar.gz" | tar -xz --strip-components=1 -C "$SRC"
else
  say "agent-guardrails needs git, or curl and tar, to fetch its files."
  exit 1
fi

# The one word. It runs the copy in $SRC with the system python3: nothing is installed into Python.
mkdir -p "$BIN"
quoted=$(printf '%s' "$SRC" | sed "s/'/'\\\\''/g")
cat > "$BIN/guardrails" <<EOF_LAUNCHER
#!/bin/sh
# agent-guardrails: this one word opens the dashboard. Written by scripts/install.sh; run that again to update.
R='$quoted'
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="\$R/packages/guardrails-core/src:\$R/packages/guardrails-dashboard/src" exec python3 -m guardrails_dashboard.cli "\$@"
EOF_LAUNCHER
chmod +x "$BIN/guardrails"
say "Installed agent-guardrails in $SRC"

if have claude; then
  "$BIN/guardrails" --install claude || say "Claude Code was not wired. Fix the error above, then run: guardrails --install claude"
else
  say "Claude Code is not on PATH. After you install it, run: guardrails --install claude"
fi
if [ -d "$HOME/.cursor" ]; then say "Cursor is on this computer. To guard it too, run: guardrails --install cursor"; fi
if [ -d "$HOME/.codex" ]; then say "Codex is on this computer. To guard it too, run: guardrails --install codex"; fi

other=$(command -v guardrails 2>/dev/null || true)
case ":$PATH:" in
  *":$BIN:"*) if [ -n "$other" ] && [ "$other" != "$BIN/guardrails" ]; then say "Another 'guardrails' comes first on your PATH ($other). Run this one as $BIN/guardrails"; fi ;;
  *) say "$BIN is not on your PATH. Add it, or run $BIN/guardrails" ;;
esac
say "Done. To open the dashboard, type: guardrails"
