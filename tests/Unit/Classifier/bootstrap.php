<?php

/**
 * Standalone bootstrap for the Classifier and Scanner unit tests (also usable from phpunit.xml):
 *
 *   docker run --rm -v <df-masking>:/src/df-masking -v <phpunit.phar>:/phpunit.phar \
 *     --entrypoint php registry.dreamfactory.com/dreamfactory/trial:7.8.0 /phpunit.phar \
 *     --bootstrap /src/df-masking/tests/Unit/Classifier/bootstrap.php \
 *     /src/df-masking/tests/Unit/Classifier /src/df-masking/tests/Unit/Scanner
 *
 * Uses DreamFactory's vendor directory (Illuminate, df-core, df-sqldb) from the image and maps
 * the package namespaces onto the mounted source. Set DM_SPIKE_DIR to the classifier
 * prototype's directory to also run the spike parity tests.
 */

$candidates = [
    getenv('DF_VENDOR_AUTOLOAD') ?: null,
    '/opt/dreamfactory/vendor/autoload.php',
    __DIR__ . '/../../../vendor/autoload.php',
];
$loader = null;
foreach ($candidates as $file) {
    if ($file && is_file($file)) {
        $loader = require $file;
        break;
    }
}
if (!$loader instanceof \Composer\Autoload\ClassLoader) {
    fwrite(STDERR, "No Composer autoloader found (set DF_VENDOR_AUTOLOAD).\n");
    exit(1);
}

$root = dirname(__DIR__, 3);
$loader->addPsr4('DreamFactory\\Core\\Masking\\', $root . '/src/', true);
$loader->addPsr4('DreamFactory\\Core\\Masking\\Tests\\', $root . '/tests/', true);

date_default_timezone_set('UTC');
