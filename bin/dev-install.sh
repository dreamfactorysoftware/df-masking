#!/usr/bin/env bash
# df-masking OFFLINE development install into a running DreamFactory container.
#
#   bin/dev-install.sh [container] [package-path-in-container]
#     container      default: dreamfactory_web_1
#     package path   default: /src/df-masking  (bind-mount the package there)
#
# What it does (idempotent; safe to re-run after pulling changes):
#   1. symlinks vendor/dreamfactory/df-masking -> <package path>
#   2. registers the package in vendor/composer/installed.json (no network, no composer
#      resolution: the root composer.json of a commercial build lists private VCS repositories)
#   3. composer dump-autoload -o (runs package:discover through the post-autoload-dump hook)
#   4. php artisan migrate --force, cache:clear, config:clear
#   5. fixes storage/bootstrap cache ownership for php-fpm
#
# Real installs do not use this script: they get the package through df-commercial's Gold tier
# (composer require dreamfactory/df-masking) - see README.md.
#
# Environment: DOCKER (default "sudo -n docker" when not root, else "docker").
set -euo pipefail

CONTAINER="${1:-dreamfactory_web_1}"
PKG="${2:-/src/df-masking}"
if [[ -z "${DOCKER:-}" ]]; then
  if [[ "$(id -u)" == "0" ]]; then DOCKER="docker"; else DOCKER="sudo -n docker"; fi
fi

say() { printf '[df-masking] %s\n' "$*"; }

if ! $DOCKER exec "$CONTAINER" test -f "$PKG/composer.json"; then
  echo "[df-masking] $PKG/composer.json not found in container $CONTAINER (bind-mount the package there)." >&2
  exit 1
fi

say "linking vendor/dreamfactory/df-masking -> $PKG"
$DOCKER exec -e PKG="$PKG" "$CONTAINER" bash -euc '
  cd /opt/dreamfactory
  target=vendor/dreamfactory/df-masking
  if [ -L "$target" ] || [ -e "$target" ]; then
    if [ "$(readlink "$target" 2>/dev/null)" != "$PKG" ]; then rm -rf "$target"; fi
  fi
  [ -L "$target" ] || ln -s "$PKG" "$target"
'

say "registering the package in vendor/composer/installed.json"
$DOCKER exec -i "$CONTAINER" php -d display_errors=stderr -- /opt/dreamfactory/vendor/composer/installed.json <<'PHP'
<?php
$file = $argv[1];
$installed = json_decode(file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
$pkg = json_decode(file_get_contents('/opt/dreamfactory/vendor/dreamfactory/df-masking/composer.json'), true, 512, JSON_THROW_ON_ERROR);
$entry = [
    'name' => $pkg['name'],
    'version' => 'dev-develop',
    'version_normalized' => 'dev-develop',
    'dist' => ['type' => 'path', 'url' => '../../../src/df-masking', 'reference' => null],
    'require' => $pkg['require'] ?? [],
    'type' => 'library',
    'extra' => $pkg['extra'] ?? [],
    'autoload' => $pkg['autoload'] + [
        // Dev install only: keep the package out of the optimized classmap so files added,
        // renamed or removed while developing resolve through PSR-4 (no stale map entries).
        'exclude-from-classmap' => ['src/'],
    ],
    'license' => [$pkg['license'] ?? 'proprietary'],
    'description' => $pkg['description'] ?? '',
    'install-path' => '../dreamfactory/df-masking',
];
$list = isset($installed['packages']) ? $installed['packages'] : $installed;
$list = array_values(array_filter($list, fn ($p) => ($p['name'] ?? '') !== $entry['name']));
$list[] = $entry;
if (isset($installed['packages'])) {
    $installed['packages'] = $list;
    $installed['dev-package-names'] = array_values(array_filter(
        $installed['dev-package-names'] ?? [],
        fn ($n) => $n !== $entry['name']
    ));
} else {
    $installed = $list;
}
file_put_contents($file, json_encode($installed, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");

// Composer only autoloads packages reachable from the root requirements, so record the
// requirement the way `composer require` would (no resolution happens: dump-autoload only).
$rootFile = '/opt/dreamfactory/composer.json';
$root = json_decode(file_get_contents($rootFile), true, 512, JSON_THROW_ON_ERROR);
if (($root['require'][$entry['name']] ?? null) !== 'dev-develop') {
    if (!file_exists($rootFile . '.before-df-masking')) {
        copy($rootFile, $rootFile . '.before-df-masking');
    }
    $root['require'][$entry['name']] = 'dev-develop';
    file_put_contents($rootFile, json_encode($root, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
}
echo "ok\n";
PHP

say "composer dump-autoload -o (offline) + package:discover"
$DOCKER exec -e COMPOSER_ALLOW_SUPERUSER=1 "$CONTAINER" bash -euc '
  cd /opt/dreamfactory
  composer dump-autoload -o --no-interaction 2>&1 | tail -n 3
'
# Never leave the instance with a registered provider it cannot autoload (every request would
# 500): verify, and roll the registration back if the class is not loadable.
if ! $DOCKER exec "$CONTAINER" php -r 'require "/opt/dreamfactory/vendor/autoload.php"; exit(class_exists("DreamFactory\\Core\\Masking\\ServiceProvider") ? 0 : 1);'; then
  echo "[df-masking] the package does not autoload; rolling the registration back" >&2
  $DOCKER exec -e COMPOSER_ALLOW_SUPERUSER=1 "$CONTAINER" bash -euc '
    cd /opt/dreamfactory
    php -r '"'"'
      $f = "vendor/composer/installed.json"; $j = json_decode(file_get_contents($f), true);
      $j["packages"] = array_values(array_filter($j["packages"], fn ($p) => ($p["name"] ?? "") !== "dreamfactory/df-masking"));
      file_put_contents($f, json_encode($j, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
      $r = "composer.json"; $c = json_decode(file_get_contents($r), true); unset($c["require"]["dreamfactory/df-masking"]);
      file_put_contents($r, json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    '"'"'
    rm -f vendor/dreamfactory/df-masking
    composer dump-autoload -o --no-interaction >/dev/null 2>&1
  '
  exit 1
fi
if ! $DOCKER exec "$CONTAINER" grep -q 'Masking.\{1,4\}ServiceProvider' /opt/dreamfactory/bootstrap/cache/packages.php; then
  echo "[df-masking] package:discover did not register DreamFactory\\Core\\Masking\\ServiceProvider" >&2
  exit 1
fi

say "migrating"
migrate_ok=1
$DOCKER exec "$CONTAINER" bash -euc '
  cd /opt/dreamfactory
  set -o pipefail
  php artisan migrate --force --no-interaction 2>&1 | grep -v "^$" | tail -n 12
' || migrate_ok=0
$DOCKER exec "$CONTAINER" bash -euc '
  cd /opt/dreamfactory
  php artisan cache:clear >/dev/null
  php artisan config:clear >/dev/null
  mkdir -p storage/framework/cache/data storage/framework/sessions storage/framework/views storage/logs bootstrap/cache
  chown -R www-data:www-data storage bootstrap/cache
'
if [[ "$migrate_ok" != 1 ]]; then
  echo "[df-masking] php artisan migrate failed (output above). Fix the cause and re-run this script." >&2
  exit 1
fi

ran="$($DOCKER exec "$CONTAINER" php /opt/dreamfactory/artisan migrate:status --no-interaction 2>/dev/null | grep '_dm_' | grep -c 'Ran' || true)"
total="$(ls "$(dirname "$0")/../database/migrations" 2>/dev/null | grep -c '\.php$' || true)"
if [[ "$ran" != "$total" ]]; then
  echo "[df-masking] only $ran of $total df-masking migrations ran" >&2
  exit 1
fi
say "installed: $ran of $total df-masking migrations ran"
