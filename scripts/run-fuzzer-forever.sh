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
COV_DIR="$CORPUS/coverage-corpus"

mkdir -p "$CORPUS" "$LOGDIR" "$COV_DIR"

# Iter-2 wakeup-3: persist the coverage-guided corpus across daily restarts. The fuzzer's
# CoverageGuidedEngineTarget reads this env var; if set, it loads any prior saved interesting
# inputs on startup and writes new ones to disk. Without this, each chunk restart loses the
# coverage-guided exploration state and the campaign re-explores the same shallow inputs.
export NEO_SYM_FUZZ_COV_DIR="$COV_DIR"

# Iter-2 wakeup-14: point real-nef target at curated DevPack/Solidity/Morpheus contract
# corpus. The target recursively scans this directory for *.nef and runs the full pipeline
# (parse → engine → detectors → report). When unset, the target trivially returns success
# and produces no useful coverage. Curate a set of distinct contracts in the corpus dir.
NEF_CORPUS="$CORPUS/real-nef-contracts"
if [ -d "$NEF_CORPUS" ]; then
  export NEO_SYM_FUZZ_NEF_DIR="$NEF_CORPUS"
fi

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

  # Log retention: keep at most 30 days of per-chunk logs and 60 days of summary files.
  # Without this the corpus directory grows unbounded over multi-week runs.
  find "$LOGDIR" -name "run-*.log" -mtime +30 -delete 2>/dev/null || true
  find "$CORPUS" -maxdepth 1 -name "summary-*.txt" -mtime +60 -delete 2>/dev/null || true

  # Run for 24 hours per chunk. The wrapper restarts the campaign daily so the log
  # files don't grow unbounded and so we can checkpoint a daily summary.
  dotnet "$FUZZER_DLL" --hours 24 --workers "$WORKERS" --corpus "$CORPUS" > "$LOGFILE" 2>&1 &
  FUZZ_PID=$!

  # Iter-2 wakeup-26: idle-log watchdog. The dotnet process can occasionally end up in
  # futex_wait with no status updates while the in-engine watchdog (which fires at
  # MaxRuntime + 2 min, i.e. 24 h + 2 min) is too distant to help. If the log hasn't
  # been written for 5 min, force-kill so the wrapper relaunches a fresh chunk.
  IDLE_LIMIT=300
  (
    while kill -0 "$FUZZ_PID" 2>/dev/null; do
      sleep 30
      if [ -f "$LOGFILE" ]; then
        last_mod=$(stat -c %Y "$LOGFILE" 2>/dev/null || echo 0)
        now=$(date +%s)
        if [ $((now - last_mod)) -gt $IDLE_LIMIT ]; then
          echo "[wrapper] log idle > ${IDLE_LIMIT}s — killing fuzzer to force restart"
          kill -KILL "$FUZZ_PID" 2>/dev/null || true
          break
        fi
      fi
    done
  ) &
  WATCHDOG_PID=$!

  if wait "$FUZZ_PID"; then
    EXIT=0
  else
    EXIT=$?
  fi
  kill $WATCHDOG_PID 2>/dev/null || true
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
      find "$CORPUS/crashes" -mindepth 1 -maxdepth 1 -type d | sort | while read -r d; do
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
