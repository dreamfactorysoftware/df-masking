<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Platform;

use DreamFactory\Core\Masking\Support\Retry;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Tests\TestCase;
use Illuminate\Support\Facades\DB;

/** Masking writes retry brief lock contention (SQLite "database is locked") instead of failing with 500. */
final class RetryTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->bootHarness();
    }

    private static function busy(): \PDOException
    {
        $e = new \PDOException('SQLSTATE[HY000]: General error: 5 database is locked');
        $e->errorInfo = ['HY000', 5, 'database is locked'];

        return $e;
    }

    public function testLockContentionIsRetriedAndTheWorkIsNotDoubled(): void
    {
        $attempts = 0;
        $result = Retry::transaction(function () use (&$attempts) {
            DB::table(Tables::MASK_FORMAT)->insert(['class' => 'email', 'format' => 'redact']);
            if (++$attempts < 3) {
                throw self::busy(); // rolled back with the transaction
            }

            return 'stored';
        });
        $this->assertSame('stored', $result);
        $this->assertSame(3, $attempts);
        $this->assertSame(1, DB::table(Tables::MASK_FORMAT)->count(), 'failed attempts were rolled back');
    }

    public function testOtherErrorsAreNotRetried(): void
    {
        $attempts = 0;
        try {
            Retry::transaction(function () use (&$attempts) {
                $attempts++;
                throw new \RuntimeException('no');
            });
            $this->fail('expected the error');
        } catch (\RuntimeException $e) {
            $this->assertSame(1, $attempts);
        }
    }

    public function testItGivesUpAfterTheLastAttempt(): void
    {
        $attempts = 0;
        $this->expectException(\PDOException::class);
        try {
            Retry::transaction(function () use (&$attempts) {
                $attempts++;
                throw self::busy();
            }, 2);
        } finally {
            $this->assertSame(2, $attempts);
        }
    }

    public function testInsideAnOuterTransactionItIsASavepointWithoutRetry(): void
    {
        DB::transaction(function () {
            try {
                Retry::transaction(function () {
                    DB::table(Tables::MASK_FORMAT)->insert(['class' => 'phone', 'format' => 'redact']);
                    throw new \RuntimeException('inner');
                });
            } catch (\RuntimeException $e) {
            }
            DB::table(Tables::MASK_FORMAT)->insert(['class' => 'email', 'format' => 'redact']);
        });
        $this->assertSame(['email'], DB::table(Tables::MASK_FORMAT)->pluck('class')->all(), 'only the inner work was rolled back');
    }

    public function testDeadlocksAreContentionToo(): void
    {
        $this->assertTrue(Retry::isContention(new \PDOException('SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock')));
        $this->assertTrue(Retry::isContention(self::busy()));
        $this->assertFalse(Retry::isContention(new \PDOException('SQLSTATE[23000]: Integrity constraint violation')));
    }
}
