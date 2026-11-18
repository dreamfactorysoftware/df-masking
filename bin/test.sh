#!/usr/bin/env bash
# Runs the df-masking unit tests with the DreamFactory image's PHP in a throwaway container.
#
#   bin/test.sh [phpunit args...]          e.g. bin/test.sh --testsuite Platform
#
# Environment:
#   DF_IMAGE      image with PHP 8.3+ and /opt/dreamfactory/vendor (default: the 7.8.0 trial image)
#   PHPUNIT_PHAR  path to a PHPUnit 11 phar on the host (default: ./phpunit.phar, git-ignored;
#                 get it with: curl -sSLo phpunit.phar https://phar.phpunit.de/phpunit-11.phar)
#   DOCKER        docker command (default: "sudo -n docker" when not root)
#   DM_UI_DIR     admin UI checkout with the Data Masking catalog (default ../df-admin-interface)
set -euo pipefail
PKG="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${DF_IMAGE:-registry.dreamfactory.com/dreamfactory/trial:7.8.0}"
PHAR="${PHPUNIT_PHAR:-}"
if [[ -z "$PHAR" ]]; then
  [[ -f "$PKG/phpunit.phar" ]] && PHAR="$PKG/phpunit.phar"
fi
[[ -f "${PHAR:-}" ]] || { echo "PHPUnit phar not found; set PHPUNIT_PHAR" >&2; exit 2; }
if [[ -z "${DOCKER:-}" ]]; then
  if [[ "$(id -u)" == "0" ]]; then DOCKER="docker"; else DOCKER="sudo -n docker"; fi
fi
# The admin UI checkout (catalog parity tests). Optional: those tests skip when it is absent.
UI="${DM_UI_DIR:-$PKG/../df-admin-interface}"
UI_MOUNT=()
if [[ -f "$UI/src/app/adf-data-masking/data-masking.catalog.ts" ]]; then
  UI_MOUNT=(-v "$UI/src/app/adf-data-masking/data-masking.catalog.ts:/ui/data-masking.catalog.ts:ro"
            -v "$UI/src/assets/i18n/dataMasking/en.json:/ui/en.json:ro"
            -e DM_UI_CATALOG=/ui/data-masking.catalog.ts -e DM_UI_I18N=/ui/en.json)
fi
# The checkout is also mounted over the image's own copy of the package: the image's optimized
# class map would otherwise load the installed df-masking classes instead of this checkout's.
exec $DOCKER run --rm --network none \
  -v "$PKG":/p:ro -v "$PKG":/opt/dreamfactory/vendor/dreamfactory/df-masking:ro \
  -v "$(cd "$(dirname "$PHAR")" && pwd)/$(basename "$PHAR")":/tools/phpunit.phar:ro \
  "${UI_MOUNT[@]}" \
  -w /p --entrypoint php "$IMAGE" -d memory_limit=1G /tools/phpunit.phar "$@"
