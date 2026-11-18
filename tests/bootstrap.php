<?php

/*
 * PHPUnit bootstrap for df-masking.
 *
 * Works in two setups:
 *  - inside a DreamFactory image / install: uses /opt/dreamfactory/vendor (Laravel, df-core, ...)
 *    and registers this package's PSR-4 namespaces on top (no composer install needed);
 *  - a standalone checkout with `composer install`: uses ./vendor.
 *
 * Unit tests that need Laravel services extend DreamFactory\Core\Masking\Tests\TestCase, which
 * builds a small container (config, array cache, in-memory SQLite system DB with the df-masking
 * tables, encrypter, events) - never the live system database.
 */

$root = dirname(__DIR__);
$candidates = array_filter([
    getenv('DF_VENDOR_AUTOLOAD') ?: null,
    $root . '/vendor/autoload.php',
    '/opt/dreamfactory/vendor/autoload.php',
]);
$loader = null;
foreach ($candidates as $file) {
    if (is_file($file)) {
        $loader = require $file;
        break;
    }
}
if (!$loader instanceof \Composer\Autoload\ClassLoader) {
    fwrite(STDERR, "df-masking tests: no Composer autoloader found (tried: " . implode(', ', $candidates) . ")\n");
    exit(1);
}

// Prepend so this checkout wins over any installed copy of the package.
$loader->addPsr4('DreamFactory\\Core\\Masking\\', $root . '/src/', true);
$loader->addPsr4('DreamFactory\\Core\\Masking\\Tests\\', $root . '/tests/', true);

date_default_timezone_set('UTC');

// The unit tests run as a Gold instance (Support\License); tests/Unit/Platform/LicenseTest.php
// covers the other license levels and the real Environment::getLicenseLevel() lookup.
\DreamFactory\Core\Masking\Support\License::resolveUsing(static fn () => \DreamFactory\Core\Enums\LicenseLevel::GOLD);
