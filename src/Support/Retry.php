<?php

namespace DreamFactory\Core\Masking\Support;

use Illuminate\Database\ConcurrencyErrorDetector;
use Illuminate\Support\Facades\DB;

/**
 * System database writes that survive brief lock contention.
 *
 * SQLite (DreamFactory's trial default system database) answers SQLITE_BUSY ("database is
 * locked") at once, without waiting, when a deferred transaction that has read tries to write
 * while another connection writes: the busy timeout does not apply to that upgrade. MySQL and
 * SQL Server report deadlocks the same way. Such a transaction is simply run again, with a short
 * jittered pause. Inside an outer transaction the work runs as a nested transaction (a savepoint)
 * without retrying: only the outermost transaction can be retried.
 */
final class Retry
{
    public const ATTEMPTS = 5;

    private function __construct()
    {
    }

    /**
     * Runs $work in a transaction on the default connection, retrying on lock contention.
     *
     * @template T
     * @param \Closure():T $work
     * @return T
     */
    public static function transaction(\Closure $work, int $attempts = self::ATTEMPTS): mixed
    {
        $conn = DB::connection();
        if ($conn->transactionLevel() > 0) {
            return $conn->transaction($work);
        }
        for ($attempt = 1; ; $attempt++) {
            try {
                return $conn->transaction($work);
            } catch (\Throwable $e) {
                if ($attempt >= $attempts || !self::isContention($e)) {
                    throw $e;
                }
                usleep(random_int(25, 75) * 1000 * $attempt);
            }
        }
    }

    /** Lock contention / deadlock / serialization failure (Laravel's detector plus SQLITE_BUSY codes). */
    public static function isContention(\Throwable $e): bool
    {
        for ($x = $e; $x !== null; $x = $x->getPrevious()) {
            if ((new ConcurrencyErrorDetector())->causedByConcurrencyError($x)) {
                return true;
            }
            if ($x instanceof \PDOException && in_array((int)($x->errorInfo[1] ?? 0), [5, 6], true)
                && ($x->errorInfo[0] ?? null) === 'HY000' && str_contains(strtolower($x->getMessage()), 'locked')) {
                return true; // SQLITE_BUSY / SQLITE_LOCKED
            }
        }

        return false;
    }
}
