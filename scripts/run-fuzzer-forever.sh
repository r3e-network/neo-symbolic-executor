#!/usr/bin/env bash
# Long-running wrapper for the Neo Symbolic Executor fuzzer.
#
# Usage:
#   scripts/run-fuzzer-forever.sh [corpus_dir] [workers]
#
# Behavior:
#   - Builds the fuzzer in Release mode if needed.
#   - Persists corpus across restarts (default: ./fuzz-corpus).
#   - Logs to ./fuzz-corpus/run.log with daily rotation.
#   - Restarts the campaign automatically if the process dies.
#   - Generates a per-day summary in ./fuzz-corpus/summary-YYYY-MM-DD.txt.
#   - Stops gracefully on SIGTERM/SIGINT (Ctrl+C).
#
# To leave running for days/weeks: run inside `nohup` or a systemd unit.
#   nohup scripts/run-fuzzer-forever.sh > /dev/null 2>&1 &
#   disown

set -euo pipefail

CORPUS=${1:-$(pwd)/fuzz-corpus}
WORKERS=${2:-$(nproc 2>/dev/null || echo 4)}
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZER_DLL="$REPO_ROOT/src/Neo.SymbolicExecutor.Fuzzer/bin/Release/net10.0/neo-sym-fuzz.dll"
LOGDIR="$CORPUS/logs"
STOP_FILE="$CORPUS/STOP"

mkdir -p "$CORPUS" "$LOGDIR"

if [ ! -f "$FUZZER_DLL" ]; then
  echo "[wrapper] building fuzzer..."
  dotnet build "$REPO_ROOT/src/Neo.SymbolicExecutor.Fuzzer/Neo.SymbolicExecutor.Fuzzer.csproj" -c Release > "$LOGDIR/build.log" 2>&1
fi

# Cleanly stop on signal.
trap 'echo "[wrapper] received stop signal, asking fuzzer to wind down..."; touch "$STOP_FILE"; if [ -n "${FUZZ_PID:-}" ]; then kill -INT "$FUZZ_PID" 2>/dev/null || true; fi; exit 0' INT TERM

while [ ! -f "$STOP_FILE" ]; do
  TS=$(date -u +%Y-%m-%dT%H-%M-%SZ)
  LOGFILE="$LOGDIR/run-$TS.log"
  echo "[wrapper] starting campaign at $TS, log=$LOGFILE"
  echo "[wrapper] corpus=$CORPUS workers=$WORKERS"

  # Run for 24 hours per chunk. The wrapper restarts the campaign daily so the log
  # files don't grow unbounded and so we can checkpoint a daily summary.
  dotnet "$FUZZER_DLL" --hours 24 --workers "$WORKERS" --corpus "$CORPUS" > "$LOGFILE" 2>&1 &
  FUZZ_PID=$!
  wait $FUZZ_PID || true
  EXIT=$?
  echo "[wrapper] campaign chunk ended with exit=$EXIT at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Daily summary.
  DATE=$(date -u +%Y-%m-%d)
  SUMMARY="$CORPUS/summary-$DATE.txt"
  {
    echo "Daily summary $DATE"
    echo "Corpus: $CORPUS"
    echo
    echo "Unique crashes recorded:"
    if [ -d "$CORPUS/crashes" ]; then
      find "$CORPUS/crashes" -mindepth 1 -maxdepth 1 -type d | sort | while read d; do
        target=$(basename "$d" | cut -d'-' -f1)
        sig=$(basename "$d")
        first=$(jq -r '.first_seen_utc // "?"' "$d/meta.json" 2>/dev/null || echo "?")
        echo "  $target  $sig  first=$first"
      done
    else
      echo "  (none)"
    fi
    echo
    echo "Tail of last log:"
    tail -n 50 "$LOGFILE" 2>/dev/null || true
  } > "$SUMMARY"
  echo "[wrapper] wrote $SUMMARY"

  # Brief pause between chunks so a tight crash loop doesn't spin.
  if [ ! -f "$STOP_FILE" ]; then sleep 5; fi
done

echo "[wrapper] STOP file present, exiting."
