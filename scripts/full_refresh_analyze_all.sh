#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${ROOT:-$HOME/Coding/multi-agent-threat-intelligence}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
REPORT_DIR="$ROOT/reports/full-refresh-$RUN_ID"
LOG="$REPORT_DIR/run.log"

# Defaults
# CVE_MODE=full means full NVD crawl/upsert. This can take a while and may hit NVD 503/rate limits.
CVE_MODE="${CVE_MODE:-full}"
CVE_DAYS="${CVE_DAYS:-30}"
CVE_LIMIT="${CVE_LIMIT:-0}"          # 0 = no explicit CLI limit
URLHAUS_LIMIT="${URLHAUS_LIMIT:-0}"  # 0 = save all fetched URLhaus recent records
FETCH_DREAD="${FETCH_DREAD:-0}"      # 0 = skip live Dread fetch
DREAD_LIMIT="${DREAD_LIMIT:-200}"
BATCH_SIZE="${BATCH_SIZE:-250}"
CONFIRM_RESET="${CONFIRM_RESET:-NO}"

mkdir -p "$REPORT_DIR"

log() {
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG"
}

run_step() {
  local name="$1"
  shift

  log ""
  log "===== START step=$name ====="
  local start
  start="$(date +%s)"

  set +e
  "$@" 2>&1 | tee -a "$LOG"
  local status=${PIPESTATUS[0]}
  set -e

  local end elapsed
  end="$(date +%s)"
  elapsed=$((end - start))

  log "===== END step=$name status=$status elapsed_seconds=$elapsed ====="

  if [[ "$status" -ne 0 ]]; then
    log "FAILED step=$name. Aborting."
    exit "$status"
  fi
}

mongo_eval() {
  docker compose exec -T mongodb mongosh threat_intel --quiet --eval "$1"
}

counts_snapshot() {
  local label="$1"
  log "--- Mongo counts snapshot: $label ---"
  mongo_eval '
const snapshot = {
  cve: {
    total: db.cve_intel.countDocuments(),
    pending: db.cve_intel.countDocuments({ processed: false }),
    processed: db.cve_intel.countDocuments({ processed: true })
  },
  urlhaus: {
    total: db.urlhaus_intel.countDocuments(),
    pending: db.urlhaus_intel.countDocuments({ processed: false }),
    processed: db.urlhaus_intel.countDocuments({ processed: true })
  },
  dread: {
    total: db.dread_intel.countDocuments(),
    pending: db.dread_intel.countDocuments({ processed: false }),
    processed: db.dread_intel.countDocuments({ processed: true })
  }
};
printjson(snapshot);
' | tee -a "$LOG"
}

pending_total() {
  mongo_eval '
const total =
  db.cve_intel.countDocuments({ processed: false }) +
  db.urlhaus_intel.countDocuments({ processed: false }) +
  db.dread_intel.countDocuments({ processed: false });
print(total);
' | tail -n 1 | tr -dc '0-9'
}

ensure_mongo() {
  cd "$ROOT"
  docker compose up -d mongodb
  docker compose ps
  docker compose exec -T mongodb mongosh --quiet --eval 'db.adminCommand({ ping: 1 })'
}

fetch_cve() {
  cd "$ROOT/agent-go"

  local args=(go run ./cmd/agent-go -source cve -mode "$CVE_MODE" -days "$CVE_DAYS")

  if [[ "$CVE_LIMIT" != "0" ]]; then
    args+=(-limit "$CVE_LIMIT")
  fi

  log "Running CVE collector: ${args[*]}"
  "${args[@]}"
}

fetch_urlhaus() {
  cd "$ROOT/agent-go"

  local args=(go run ./cmd/agent-go -source urlhaus)

  if [[ "$URLHAUS_LIMIT" != "0" ]]; then
    args+=(-limit "$URLHAUS_LIMIT")
  fi

  log "Running URLhaus collector: ${args[*]}"
  "${args[@]}"
}

fetch_dread() {
  if [[ "$FETCH_DREAD" != "1" ]]; then
    log "Skipping live Dread fetch. Set FETCH_DREAD=1 to enable."
    return 0
  fi

  cd "$ROOT/agent-go"

  local args=(go run ./cmd/agent-go -source dread)

  if [[ "$DREAD_LIMIT" != "0" ]]; then
    args+=(-limit "$DREAD_LIMIT")
  fi

  log "Running Dread collector: ${args[*]}"
  log "Note: Dread requires its own environment/browser/Tor setup. If it is not configured, this step may fail."
  "${args[@]}"
}

reset_all_to_pending() {
  if [[ "$CONFIRM_RESET" != "YES" ]]; then
    log "Refusing to reset processed flags. Re-run with CONFIRM_RESET=YES."
    exit 3
  fi

  log "Resetting all cve/urlhaus/dread documents to processed=false."
  log "This preserves analysis/history but clears lifecycle/analyzed_at so the worker can claim the jobs again."

  mongo_eval '
const sources = [
  { source: "cve", collection: "cve_intel" },
  { source: "urlhaus", collection: "urlhaus_intel" },
  { source: "dread", collection: "dread_intel" }
];

for (const item of sources) {
  const coll = db.getCollection(item.collection);
  const before = {
    total: coll.countDocuments(),
    pending: coll.countDocuments({ processed: false }),
    processed: coll.countDocuments({ processed: true })
  };

  const result = coll.updateMany(
    {},
    {
      $set: { processed: false },
      $unset: {
        job_lifecycle: "",
        job_lifecycle_history: "",
        analyzed_at: ""
      }
    }
  );

  const after = {
    total: coll.countDocuments(),
    pending: coll.countDocuments({ processed: false }),
    processed: coll.countDocuments({ processed: true })
  };

  printjson({
    source: item.source,
    collection: item.collection,
    before,
    matched: result.matchedCount,
    modified: result.modifiedCount,
    after
  });
}
' | tee -a "$LOG"
}

analyze_until_done() {
  cd "$ROOT/agent-python"

  local cycle=0
  local no_progress_count=0

  while true; do
    local pending_before
    pending_before="$(pending_total)"

    log "Analysis loop cycle=$cycle pending_before=$pending_before batch_size=$BATCH_SIZE"

    if [[ "$pending_before" -eq 0 ]]; then
      log "No pending records left. Analysis complete."
      break
    fi

    local start
    start="$(date +%s)"

    python src/main.py --source all --run-once --batch-size "$BATCH_SIZE" 2>&1 | tee -a "$LOG"
    local status=${PIPESTATUS[0]}

    local end elapsed
    end="$(date +%s)"
    elapsed=$((end - start))

    if [[ "$status" -ne 0 ]]; then
      log "Worker failed in cycle=$cycle status=$status elapsed_seconds=$elapsed"
      exit "$status"
    fi

    local pending_after
    pending_after="$(pending_total)"

    log "Analysis loop cycle=$cycle pending_after=$pending_after cycle_elapsed_seconds=$elapsed"

    if [[ "$pending_after" -ge "$pending_before" ]]; then
      no_progress_count=$((no_progress_count + 1))
      log "No pending reduction detected. no_progress_count=$no_progress_count"

      if [[ "$no_progress_count" -ge 3 ]]; then
        log "Aborting after 3 no-progress cycles to avoid infinite loop."
        exit 4
      fi
    else
      no_progress_count=0
    fi

    cycle=$((cycle + 1))
  done
}

main() {
  local global_start
  global_start="$(date +%s)"

  log "Full refresh/analyze run_id=$RUN_ID"
  log "ROOT=$ROOT"
  log "CVE_MODE=$CVE_MODE CVE_DAYS=$CVE_DAYS CVE_LIMIT=$CVE_LIMIT"
  log "URLHAUS_LIMIT=$URLHAUS_LIMIT FETCH_DREAD=$FETCH_DREAD DREAD_LIMIT=$DREAD_LIMIT"
  log "BATCH_SIZE=$BATCH_SIZE"

  run_step "ensure_mongo" ensure_mongo
  counts_snapshot "before_fetch"

  run_step "fetch_cve" fetch_cve
  run_step "fetch_urlhaus" fetch_urlhaus
  run_step "fetch_dread" fetch_dread

  counts_snapshot "after_fetch"

  run_step "reset_all_to_pending" reset_all_to_pending
  counts_snapshot "after_reset"

  run_step "analyze_until_done" analyze_until_done
  counts_snapshot "after_analysis"

  local global_end total_elapsed
  global_end="$(date +%s)"
  total_elapsed=$((global_end - global_start))

  log "FULL_REFRESH_DONE run_id=$RUN_ID total_elapsed_seconds=$total_elapsed"
  log "Log file: $LOG"
}

main "$@"
