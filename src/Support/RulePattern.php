<?php

namespace DreamFactory\Core\Masking\Support;

/**
 * Admin detection-rule patterns: PCRE, case-insensitive, UTF-8, at most 500 characters,
 * written WITHOUT delimiters (e.g. "(^|_)(ssn|nino|bsn)($|_)").
 *
 * Evaluation is guarded: the PCRE JIT is turned off and pcre.backtrack_limit lowered
 * (df-masking.rules.backtrack_limit) while an admin pattern runs, so a catastrophic pattern
 * fails fast with an error instead of pinning a PHP worker. validate() also runs the pattern
 * against adversarial probes and rejects patterns that blow the limit.
 *
 * Use matches() (or withLimits() around your own preg_* calls) for every evaluation of an
 * admin pattern, in the API and in the scanner alike.
 */
final class RulePattern
{
    public const MAX_LENGTH = 500;

    private const DELIMITER = "\x01";

    /** Inputs that make exponential patterns such as (a+)+$ backtrack. Synthetic. */
    private const PROBES = [
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!',
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000x',
        'customer_email_address_primary_contact_name_and_phone_number_and_street_address_and_postal_code_and_more_columns_x',
        '                                                                                                                 !',
    ];

    private function __construct()
    {
    }

    /**
     * Null when valid, otherwise a message for the admin ("Not a valid pattern: ...").
     */
    public static function validate(mixed $pattern): ?string
    {
        if (!is_string($pattern) || trim($pattern) === '') {
            return 'Enter a pattern.';
        }
        if (mb_strlen($pattern) > self::MAX_LENGTH) {
            return 'Patterns can be at most ' . self::MAX_LENGTH . ' characters.';
        }
        if (!mb_check_encoding($pattern, 'UTF-8')) {
            return 'Patterns must be valid UTF-8.';
        }
        if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $pattern)) {
            return 'Patterns cannot contain control characters.';
        }

        $regex = self::compile($pattern);
        $error = self::withLimits(static function () use ($regex): ?string {
            [$result, $warning] = self::capture(static fn () => preg_match($regex, ''));
            if ($result === false) {
                return 'Not a valid pattern: ' . self::describe($warning);
            }
            foreach (self::PROBES as $probe) {
                [$result, $warning] = self::capture(static fn () => preg_match($regex, $probe));
                if ($result === false) {
                    return preg_last_error() === PREG_BACKTRACK_LIMIT_ERROR
                        ? 'This pattern is too complex to evaluate safely; simplify nested repetition such as (a+)+.'
                        : 'Not a valid pattern: ' . self::describe($warning);
                }
            }

            return null;
        });

        return $error;
    }

    /** The delimited, case-insensitive UTF-8 regex for an (undelimited) admin pattern. */
    public static function compile(string $pattern): string
    {
        return self::DELIMITER . $pattern . self::DELIMITER . 'iu';
    }

    /**
     * Guarded match of an already compiled pattern. A runtime error (backtrack limit, invalid
     * UTF-8 subject) counts as "no match".
     */
    public static function matches(string $compiled, string $subject): bool
    {
        return self::withLimits(static fn () => @preg_match($compiled, $subject) === 1);
    }

    /**
     * Runs $fn with the PCRE JIT off and the lowered backtrack limit, restoring both after.
     *
     * @template T
     * @param callable():T $fn
     * @return T
     */
    public static function withLimits(callable $fn): mixed
    {
        try {
            $limit = (int)config('df-masking.rules.backtrack_limit', 100000);
        } catch (\Throwable $e) {
            $limit = 100000; // no application container (bare unit tests)
        }
        $limit = $limit > 0 ? $limit : 100000;
        $oldJit = ini_get('pcre.jit');
        $oldLimit = ini_get('pcre.backtrack_limit');
        @ini_set('pcre.jit', '0');
        @ini_set('pcre.backtrack_limit', (string)$limit);
        try {
            return $fn();
        } finally {
            @ini_set('pcre.backtrack_limit', $oldLimit === false ? '1000000' : (string)$oldLimit);
            @ini_set('pcre.jit', $oldJit === false ? '1' : (string)$oldJit);
        }
    }

    /**
     * Runs a preg_* call with a temporary error handler, so the compile warning text is captured
     * even when the framework has its own handler installed.
     *
     * @return array{0:mixed,1:?string} [result, warning message]
     */
    private static function capture(callable $fn): array
    {
        $warning = null;
        set_error_handler(static function (int $no, string $message) use (&$warning): bool {
            $warning = $message;

            return true;
        });
        try {
            $result = $fn();
        } finally {
            restore_error_handler();
        }

        return [$result, $warning];
    }

    /** "preg_match(): Compilation failed: missing closing parenthesis at offset 4" -> readable text. */
    private static function describe(?string $warning): string
    {
        $message = $warning !== null && $warning !== ''
            ? preg_replace('/^preg_\w+\(\):\s*/', '', $warning)
            : preg_last_error_msg();
        $message = (string)preg_replace('/^Compilation failed:\s*/i', '', (string)$message);

        return ucfirst(rtrim($message, '.')) . '.';
    }
}
