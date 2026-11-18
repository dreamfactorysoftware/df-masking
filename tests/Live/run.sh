#!/usr/bin/env bash
# Runs the df-masking live suites against a running DreamFactory with the package installed.
#
#   tests/Live/run.sh [enforcement|filters|cleanup|baselines|perf|values|all] [enforcement check names...]
#
# Environment: see tests/Live/README.md (DM_BASE_URL, DM_ADMIN_*, DM_API_KEY, DM_MYSQL, DM_PG,
# DM_WEB_CONTAINER, DM_EVIDENCE_DIR). The suites change masking settings and restore them; run them
# on a test instance with synthetic data only.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WHAT="${1:-all}"; shift || true
DOCKER="${DM_DOCKER:-sudo -n docker}"
WEB="${DM_WEB_CONTAINER:?set DM_WEB_CONTAINER to the DreamFactory web container}"
status=0
run() { echo "== $1"; shift; "$@" || status=1; }
case "$WHAT" in
  enforcement) run enforcement python3 -I "$HERE/enforcement.py" "${@:-all}" ;;
  filters)     run filters python3 -I "$HERE/filters.py" ;;
  cleanup)     run cleanup python3 -I "$HERE/cleanup.py" ;;
  baselines)   run baselines python3 -I "$HERE/baselines.py" ;;
  perf)        run perf python3 -I "$HERE/perf.py" ;;
  values)      run values bash -c "$DOCKER exec -i -u www-data $WEB php -d memory_limit=1G < '$HERE/valuecheck.php'" ;;
  all)
    run enforcement python3 -I "$HERE/enforcement.py" all
    run filters python3 -I "$HERE/filters.py"
    run cleanup python3 -I "$HERE/cleanup.py"
    run baselines python3 -I "$HERE/baselines.py"
    run perf python3 -I "$HERE/perf.py"
    run values bash -c "$DOCKER exec -i -u www-data $WEB php -d memory_limit=1G < '$HERE/valuecheck.php'"
    ;;
  *) echo "unknown suite: $WHAT" >&2; exit 2 ;;
esac
exit $status
