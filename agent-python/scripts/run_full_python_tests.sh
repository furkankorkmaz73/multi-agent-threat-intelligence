#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_PYTHON_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${AGENT_PYTHON_DIR}/.." && pwd)"
PYTHON_BIN="${PYTHON:-${AGENT_PYTHON_DIR}/.venv/bin/python}"
MONGO_URI="${MONGO_URI:-mongodb://127.0.0.1:27017}"
PYTEST_OUTPUT="$(mktemp)"

cleanup() {
  rm -f "${PYTEST_OUTPUT}"
}
trap cleanup EXIT

if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="${PYTHON:-python}"
fi

echo "Full Python test profile"
echo "Python: ${PYTHON_BIN}"
echo "MongoDB: ${MONGO_URI}"

echo "Checking optional sklearn dependencies..."
PYTHONPATH="${AGENT_PYTHON_DIR}/src" "${PYTHON_BIN}" - <<'PY'
try:
    import sklearn  # noqa: F401
    from sklearn import metrics  # noqa: F401
    from sklearn.dummy import DummyClassifier  # noqa: F401
    from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier  # noqa: F401
    from sklearn.linear_model import LogisticRegression  # noqa: F401
    from sklearn.model_selection import train_test_split  # noqa: F401
except ImportError as exc:
    raise SystemExit(
        "Missing optional sklearn test dependency. "
        "Install with: cd agent-python && .venv/bin/python -m pip install -r requirements-test.txt\n"
        f"Import error: {exc}"
    )
PY

mongo_ping() {
  PYTHONPATH="${AGENT_PYTHON_DIR}/src" MONGO_URI="${MONGO_URI}" "${PYTHON_BIN}" - <<'PY'
import os
import sys

import pymongo

try:
    client = pymongo.MongoClient(
        os.environ["MONGO_URI"],
        serverSelectionTimeoutMS=1200,
        connectTimeoutMS=1200,
    )
    client.admin.command("ping")
except Exception:
    sys.exit(1)
PY
}

if mongo_ping; then
  echo "MongoDB ping succeeded."
else
  echo "MongoDB is unavailable; starting docker compose service: mongodb"
  (cd "${REPO_ROOT}" && docker compose up -d mongodb)
fi

echo "Waiting for MongoDB ping..."
deadline=$((SECONDS + 60))
until mongo_ping; do
  if (( SECONDS >= deadline )); then
    echo "Timed out waiting for MongoDB at ${MONGO_URI}" >&2
    exit 1
  fi
  sleep 1
done
echo "MongoDB ping succeeded."

echo "Running pytest with RUN_E2E_SYSTEM=1 and SKLEARN_OPTIONAL_TESTS=1..."
set +e
(
  cd "${AGENT_PYTHON_DIR}"
  RUN_E2E_SYSTEM=1 \
  SKLEARN_OPTIONAL_TESTS=1 \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=src \
  "${PYTHON_BIN}" -m pytest tests -rs -q
) 2>&1 | tee "${PYTEST_OUTPUT}"
pytest_status=${PIPESTATUS[0]}
set -e

if (( pytest_status != 0 )); then
  echo "Full Python test profile failed with pytest exit code ${pytest_status}." >&2
  exit "${pytest_status}"
fi

if grep -Eq '(^SKIPPED \[|[0-9]+ skipped)' "${PYTEST_OUTPUT}"; then
  echo "Full Python test profile failed: pytest still reported skipped tests." >&2
  exit 1
fi

summary="$(grep -E '^[0-9]+ passed(, [0-9]+ [a-z]+)* in [0-9.]+s$' "${PYTEST_OUTPUT}" | tail -n 1 || true)"
echo "Full Python test profile passed with 0 skipped tests."
if [[ -n "${summary}" ]]; then
  echo "${summary}"
fi
