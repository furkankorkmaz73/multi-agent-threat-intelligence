#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$HOME/Coding/multi-agent-threat-intelligence"
BATCH_SIZE="${BATCH_SIZE:-250}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
REPORT_DIR="$ROOT/reports/reanalysis-$RUN_ID"
LOG_FILE="$REPORT_DIR/reanalysis.log"

mkdir -p "$REPORT_DIR"

log() {
  printf '%s | %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG_FILE"
}

mongo_eval() {
  (
    cd "$ROOT"
    docker compose exec -T mongodb \
      mongosh threat_intel --quiet --eval "$1"
  )
}

pending_total() {
  mongo_eval '
const total =
  db.cve_intel.countDocuments({ processed: false }) +
  db.urlhaus_intel.countDocuments({ processed: false }) +
  db.dread_intel.countDocuments({ processed: false });

print(total);
' | tail -n 1 | tr -dc "0-9"
}

print_counts() {
  mongo_eval '
printjson({
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
});
' | tee -a "$LOG_FILE"
}

print_blocked_samples() {
  mongo_eval '
const collections = [
  { source: "cve", collection: db.cve_intel },
  { source: "urlhaus", collection: db.urlhaus_intel },
  { source: "dread", collection: db.dread_intel }
];

for (const item of collections) {
  print("SOURCE=" + item.source);

  const states = item.collection.aggregate([
    { $match: { processed: false } },
    {
      $group: {
        _id: { $ifNull: ["$job_lifecycle.state", "missing"] },
        count: { $sum: 1 }
      }
    },
    { $sort: { count: -1 } }
  ]).toArray();

  printjson(states);

  const samples = item.collection.find(
    { processed: false },
    {
      _id: 1,
      url: 1,
      title: 1,
      "job_lifecycle.state": 1,
      "job_lifecycle.last_error": 1
    }
  ).limit(10).toArray();

  printjson(samples);
}
' | tee -a "$LOG_FILE"
}

GLOBAL_START="$(date +%s)"
CYCLE=0
NO_PROGRESS_COUNT=0

log "Re-analysis started"
log "run_id=$RUN_ID"
log "batch_size=$BATCH_SIZE"
log "log_file=$LOG_FILE"

log "Initial collection state:"
print_counts

while true; do
  PENDING_BEFORE="$(pending_total)"

  if [[ -z "$PENDING_BEFORE" ]]; then
    log "Could not read pending count."
    exit 2
  fi

  if [[ "$PENDING_BEFORE" -eq 0 ]]; then
    log "No pending records remain."
    break
  fi

  CYCLE=$((CYCLE + 1))
  CYCLE_START="$(date +%s)"

  log ""
  log "===== cycle=$CYCLE pending_before=$PENDING_BEFORE ====="

  set +e
  (
    cd "$ROOT/agent-python"
    python src/main.py \
      --source all \
      --run-once \
      --batch-size "$BATCH_SIZE"
  ) 2>&1 | tee -a "$LOG_FILE"

  WORKER_STATUS=${PIPESTATUS[0]}
  set -e

  CYCLE_END="$(date +%s)"
  CYCLE_ELAPSED=$((CYCLE_END - CYCLE_START))
  PENDING_AFTER="$(pending_total)"
  PROCESSED_DELTA=$((PENDING_BEFORE - PENDING_AFTER))

  log "cycle=$CYCLE worker_status=$WORKER_STATUS"
  log "cycle=$CYCLE elapsed_seconds=$CYCLE_ELAPSED"
  log "cycle=$CYCLE processed_delta=$PROCESSED_DELTA"
  log "cycle=$CYCLE pending_after=$PENDING_AFTER"

  if [[ "$WORKER_STATUS" -ne 0 ]]; then
    log "Worker failed. Stopping."
    print_blocked_samples
    exit "$WORKER_STATUS"
  fi

  if [[ "$PROCESSED_DELTA" -le 0 ]]; then
    NO_PROGRESS_COUNT=$((NO_PROGRESS_COUNT + 1))
    log "No progress detected. no_progress_count=$NO_PROGRESS_COUNT"

    if [[ "$NO_PROGRESS_COUNT" -ge 3 ]]; then
      log "Stopping after three cycles without progress."
      print_blocked_samples
      exit 4
    fi
  else
    NO_PROGRESS_COUNT=0
  fi
done

GLOBAL_END="$(date +%s)"
TOTAL_ELAPSED=$((GLOBAL_END - GLOBAL_START))

log ""
log "Final collection state:"
print_counts

log "REANALYSIS_COMPLETED"
log "cycles=$CYCLE"
log "total_elapsed_seconds=$TOTAL_ELAPSED"
log "total_elapsed_minutes=$((TOTAL_ELAPSED / 60))"
log "report_directory=$REPORT_DIR"
