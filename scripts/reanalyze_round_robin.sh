#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${ROOT:-$HOME/Coding/multi-agent-threat-intelligence}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
REPORT_DIR="$ROOT/reports/reanalysis-round-robin-$RUN_ID"
LOG_FILE="$REPORT_DIR/reanalysis.log"
CSV_FILE="$REPORT_DIR/source_metrics.csv"

# RESET_ALL=YES yalnızca ilk çalıştırmada kullanılmalı.
# Yarım kalan analize devam ederken RESET_ALL=NO kullanılmalı.
RESET_ALL="${RESET_ALL:-NO}"

# Kaynak bazlı batch boyutları.
CVE_BATCH_SIZE="${CVE_BATCH_SIZE:-250}"
URLHAUS_BATCH_SIZE="${URLHAUS_BATCH_SIZE:-250}"
DREAD_BATCH_SIZE="${DREAD_BATCH_SIZE:-100}"

MAX_NO_PROGRESS_ROUNDS="${MAX_NO_PROGRESS_ROUNDS:-3}"

SOURCES=("cve" "urlhaus" "dread")

mkdir -p "$REPORT_DIR"

printf '%s\n' \
  "timestamp,round,source,batch_size,pending_before,processed_delta,pending_after,elapsed_seconds,status" \
  > "$CSV_FILE"

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

collection_for_source() {
  case "$1" in
    cve)
      printf '%s' "cve_intel"
      ;;
    urlhaus)
      printf '%s' "urlhaus_intel"
      ;;
    dread)
      printf '%s' "dread_intel"
      ;;
    *)
      log "Unknown source: $1"
      return 1
      ;;
  esac
}

batch_size_for_source() {
  case "$1" in
    cve)
      printf '%s' "$CVE_BATCH_SIZE"
      ;;
    urlhaus)
      printf '%s' "$URLHAUS_BATCH_SIZE"
      ;;
    dread)
      printf '%s' "$DREAD_BATCH_SIZE"
      ;;
    *)
      return 1
      ;;
  esac
}

pending_for_source() {
  local source="$1"
  local collection
  collection="$(collection_for_source "$source")"

  mongo_eval "
print(db.${collection}.countDocuments({ processed: false }));
" | tail -n 1 | tr -dc '0-9'
}

total_pending() {
  mongo_eval '
const total =
  db.cve_intel.countDocuments({ processed: false }) +
  db.urlhaus_intel.countDocuments({ processed: false }) +
  db.dread_intel.countDocuments({ processed: false });

print(total);
' | tail -n 1 | tr -dc '0-9'
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

ensure_mongo() {
  cd "$ROOT"

  docker compose up -d mongodb

  docker compose exec -T mongodb \
    mongosh --quiet --eval 'db.adminCommand({ ping: 1 })'
}

reset_all_to_pending() {
  if [[ "$RESET_ALL" != "YES" ]]; then
    log "RESET_ALL=$RESET_ALL; mevcut pending state korunuyor."
    return 0
  fi

  log "Bütün CVE, URLhaus ve Dread kayıtları pending yapılıyor."

  mongo_eval '
const collections = [
  { source: "cve", name: "cve_intel" },
  { source: "urlhaus", name: "urlhaus_intel" },
  { source: "dread", name: "dread_intel" }
];

for (const item of collections) {
  const collection = db.getCollection(item.name);

  const before = {
    total: collection.countDocuments(),
    pending: collection.countDocuments({ processed: false }),
    processed: collection.countDocuments({ processed: true })
  };

  const result = collection.updateMany(
    {},
    {
      $set: {
        processed: false
      },
      $unset: {
        job_lifecycle: "",
        job_lifecycle_updated_at: "",
        analyzed_at: ""
      }
    }
  );

  const after = {
    total: collection.countDocuments(),
    pending: collection.countDocuments({ processed: false }),
    processed: collection.countDocuments({ processed: true })
  };

  printjson({
    source: item.source,
    matched: result.matchedCount,
    modified: result.modifiedCount,
    before,
    after
  });
}
' | tee -a "$LOG_FILE"
}

print_blocked_state() {
  mongo_eval '
const collections = [
  { source: "cve", collection: db.cve_intel },
  { source: "urlhaus", collection: db.urlhaus_intel },
  { source: "dread", collection: db.dread_intel }
];

for (const item of collections) {
  const states = item.collection.aggregate([
    {
      $match: {
        processed: false
      }
    },
    {
      $group: {
        _id: {
          $ifNull: ["$job_lifecycle.state", "missing"]
        },
        count: {
          $sum: 1
        }
      }
    },
    {
      $sort: {
        count: -1
      }
    }
  ]).toArray();

  printjson({
    source: item.source,
    pending_states: states
  });
}
' | tee -a "$LOG_FILE"
}

run_source_batch() {
  local round="$1"
  local source="$2"
  local batch_size
  local pending_before
  local pending_after
  local processed_delta
  local started_at
  local finished_at
  local elapsed
  local worker_status

  batch_size="$(batch_size_for_source "$source")"
  pending_before="$(pending_for_source "$source")"

  if [[ -z "$pending_before" ]]; then
    log "source=$source pending sayısı okunamadı."
    return 2
  fi

  if [[ "$pending_before" -eq 0 ]]; then
    log "round=$round source=$source pending=0; kaynak atlanıyor."

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$(date --iso-8601=seconds)" \
      "$round" \
      "$source" \
      "$batch_size" \
      "0" \
      "0" \
      "0" \
      "0" \
      "skipped" \
      >> "$CSV_FILE"

    return 0
  fi

  log ""
  log "----- ROUND $round / SOURCE $source -----"
  log "source=$source pending_before=$pending_before batch_size=$batch_size"

  started_at="$(date +%s)"

  set +e
  (
    cd "$ROOT/agent-python"

    python src/main.py \
      --source "$source" \
      --run-once \
      --batch-size "$batch_size"
  ) 2>&1 | tee -a "$LOG_FILE"

  worker_status=${PIPESTATUS[0]}
  set -e

  finished_at="$(date +%s)"
  elapsed=$((finished_at - started_at))

  pending_after="$(pending_for_source "$source")"

  if [[ -z "$pending_after" ]]; then
    log "source=$source işlem sonrası pending sayısı okunamadı."
    return 2
  fi

  processed_delta=$((pending_before - pending_after))

  log "source=$source worker_status=$worker_status"
  log "source=$source elapsed_seconds=$elapsed"
  log "source=$source processed_delta=$processed_delta"
  log "source=$source pending_after=$pending_after"

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(date --iso-8601=seconds)" \
    "$round" \
    "$source" \
    "$batch_size" \
    "$pending_before" \
    "$processed_delta" \
    "$pending_after" \
    "$elapsed" \
    "$worker_status" \
    >> "$CSV_FILE"

  if [[ "$worker_status" -ne 0 ]]; then
    return "$worker_status"
  fi
}

main() {
  local global_started_at
  local global_finished_at
  local total_elapsed
  local round=0
  local no_progress_rounds=0
  local pending_before_round
  local pending_after_round
  local processed_in_round

  global_started_at="$(date +%s)"

  log "Round-robin re-analysis başlatılıyor."
  log "run_id=$RUN_ID"
  log "source_order=${SOURCES[*]}"
  log "cve_batch_size=$CVE_BATCH_SIZE"
  log "urlhaus_batch_size=$URLHAUS_BATCH_SIZE"
  log "dread_batch_size=$DREAD_BATCH_SIZE"
  log "reset_all=$RESET_ALL"
  log "report_directory=$REPORT_DIR"

  ensure_mongo
  reset_all_to_pending

  log ""
  log "Başlangıç collection durumu:"
  print_counts

  while true; do
    pending_before_round="$(total_pending)"

    if [[ -z "$pending_before_round" ]]; then
      log "Toplam pending sayısı okunamadı."
      exit 2
    fi

    if [[ "$pending_before_round" -eq 0 ]]; then
      log "Pending kayıt kalmadı."
      break
    fi

    round=$((round + 1))

    log ""
    log "=================================================="
    log "ROUND $round START pending_total=$pending_before_round"
    log "ORDER: cve -> urlhaus -> dread"
    log "=================================================="

    # Deterministik round-robin:
    # Her turda her kaynaktan yalnızca bir bounded batch işlenir.
    for source in "${SOURCES[@]}"; do
      if ! run_source_batch "$round" "$source"; then
        log "Worker başarısız oldu. round=$round source=$source"
        print_blocked_state
        exit 3
      fi
    done

    pending_after_round="$(total_pending)"
    processed_in_round=$((pending_before_round - pending_after_round))

    log ""
    log "ROUND $round END"
    log "pending_before=$pending_before_round"
    log "processed_in_round=$processed_in_round"
    log "pending_after=$pending_after_round"

    if [[ "$processed_in_round" -le 0 ]]; then
      no_progress_rounds=$((no_progress_rounds + 1))

      log "İlerleme yok. no_progress_rounds=$no_progress_rounds"

      if [[ "$no_progress_rounds" -ge "$MAX_NO_PROGRESS_ROUNDS" ]]; then
        log "Üç tur ilerleme olmadığı için işlem durduruluyor."
        print_blocked_state
        exit 4
      fi
    else
      no_progress_rounds=0
    fi
  done

  global_finished_at="$(date +%s)"
  total_elapsed=$((global_finished_at - global_started_at))

  log ""
  log "Final collection durumu:"
  print_counts

  log ""
  log "REANALYSIS_COMPLETED"
  log "rounds=$round"
  log "total_elapsed_seconds=$total_elapsed"
  log "total_elapsed_minutes=$((total_elapsed / 60))"
  log "log_file=$LOG_FILE"
  log "metrics_csv=$CSV_FILE"
}

main "$@"
