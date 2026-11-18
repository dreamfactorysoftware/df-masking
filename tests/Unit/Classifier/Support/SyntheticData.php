<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Classifier\Support;

/**
 * Deterministic synthetic database for golden tests: table definitions plus sampled rows, built
 * with a fixed linear congruential generator (independent of PHP's RNG implementation). Every
 * value is synthetic and obviously fake.
 *
 * Returned as plain arrays so both the df-masking engine and the classifier prototype (parity
 * harness) can build their own TableMeta/ColumnMeta objects from it.
 */
final class SyntheticData
{
    private int $x;

    private const GIVEN = ['James', 'Mary', 'John', 'Patricia', 'Robert', 'Jennifer', 'Michael', 'Linda', 'David', 'Elizabeth', 'Wei', 'Priya', 'Lars', 'Ingrid', 'Ana', 'Lucas'];
    private const SUR = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Martinez', 'Wilson', 'Anderson', 'Taylor', 'Nguyen', 'Patel', 'Kim', 'Chen'];
    private const WORDS = ['the', 'customer', 'asked', 'about', 'delivery', 'window', 'and', 'refund', 'policy', 'please', 'call', 'back', 'tomorrow', 'regarding', 'invoice', 'order'];
    private const PRODUCTS = ['Widget', 'Gadget', 'Sprocket', 'Gizmo', 'Doohickey', 'Thingamajig'];

    public function __construct(int $seed = 20261029)
    {
        $this->x = $seed;
    }

    /**
     * @return array{tables: list<array{name:string, columns:list<array>, pk:list<string>}>, rows: array<string,list<array<string,?string>>>}
     *   column = [name, db_type, df_type, size, is_pk, is_fk, ref_table, comment]
     */
    public static function build(int $rows = 160): array
    {
        $g = new self();
        $tables = [
            ['name' => 'customers', 'pk' => ['id'], 'columns' => [
                ['id', 'integer', 'integer', null, true, false, null, null],
                ['first_name', 'character varying(40)', 'string', 40, false, false, null, null],
                ['last_name', 'character varying(40)', 'string', 40, false, false, null, null],
                ['email', 'character varying(120)', 'string', 120, false, false, null, null],
                ['phone', 'character varying(20)', 'string', 20, false, false, null, null],
                ['ssn', 'character(11)', 'string', 11, false, false, null, null],
                ['birth_date', 'date', 'date', null, false, false, null, null],
                ['created_at', 'timestamp without time zone', 'timestamp', null, false, false, null, null],
                ['notes', 'text', 'text', null, false, false, null, null],
                ['fld7', 'character varying(20)', 'string', 20, false, false, null, 'Tax identification number of the customer'],
                ['status', 'character varying(10)', 'string', 10, false, false, null, null],
            ]],
            ['name' => 'payments', 'pk' => ['id'], 'columns' => [
                ['id', 'integer', 'integer', null, true, false, null, null],
                ['customer_id', 'integer', 'integer', null, false, true, 'customers', null],
                ['pan', 'character varying(19)', 'string', 19, false, false, null, null],
                ['card_exp', 'character varying(5)', 'string', 5, false, false, null, null],
                ['amount', 'numeric(10,2)', 'decimal', null, false, false, null, null],
                ['payload', 'jsonb', 'jsonb', null, false, false, null, null],
            ]],
            ['name' => 'products', 'pk' => ['sku'], 'columns' => [
                ['sku', 'character varying(12)', 'string', 12, true, false, null, null],
                ['name', 'character varying(60)', 'string', 60, false, false, null, null],
                ['price', 'numeric(8,2)', 'decimal', null, false, false, null, null],
                ['email', 'character(1)', 'string', 1, false, false, null, null],
            ]],
            ['name' => 'audit_log', 'pk' => [], 'columns' => [
                ['ip', 'inet', 'string', null, false, false, null, null],
                ['user_agent', 'text', 'text', null, false, false, null, null],
                ['token', 'character varying(64)', 'string', 64, false, false, null, null],
            ]],
        ];
        $data = [];
        for ($i = 0; $i < $rows; $i++) {
            $first = $g->pick(self::GIVEN);
            $last = $g->pick(self::SUR);
            $data['customers'][] = [
                'id' => (string) ($i + 1),
                'first_name' => $first,
                'last_name' => $last,
                'email' => strtolower($first . '.' . $last) . ($i + 1) . '@example.com',
                'phone' => sprintf('(%d%02d) %d%02d-%04d', $g->r(2, 9), $g->r(0, 99), $g->r(2, 9), $g->r(0, 99), $g->r(0, 9999)),
                'ssn' => sprintf('%03d-%02d-%04d', $g->ssnArea(), $g->r(1, 99), $g->r(1, 9999)),
                'birth_date' => sprintf('%04d-%02d-%02d', $g->r(1940, 2004), $g->r(1, 12), $g->r(1, 28)),
                'created_at' => sprintf('2026-%02d-%02d %02d:%02d:%02d', $g->r(1, 9), $g->r(1, 28), $g->r(0, 23), $g->r(0, 59), $g->r(0, 59)),
                'notes' => $g->prose($i % 3 === 0 ? strtolower($first) . '.' . strtolower($last) . '@example.org' : null),
                'fld7' => sprintf('9%02d-%02d-%04d', $g->r(0, 99), $g->r(70, 88), $g->r(0, 9999)),
                'status' => $g->pick(['active', 'inactive', 'pending']),
            ];
            $data['payments'][] = [
                'id' => (string) ($i + 1),
                'customer_id' => (string) $g->r(1, $rows),
                'pan' => $g->card(),
                'card_exp' => sprintf('%02d/%02d', $g->r(1, 12), $g->r(27, 31)),
                'amount' => sprintf('%d.%02d', $g->r(1, 900), $g->r(0, 99)),
                'payload' => json_encode(['customer' => ['email' => 'buyer' . ($i + 1) . '@example.net', 'tier' => $g->pick(['gold', 'silver'])], 'n' => $i]),
            ];
            $data['products'][] = [
                'sku' => sprintf('SKU-%05d', $i + 1),
                'name' => $g->pick(self::PRODUCTS) . ' ' . $g->pick(['Mini', 'Pro', 'Max', 'Lite']),
                'price' => sprintf('%d.%02d', $g->r(1, 300), $g->r(0, 99)),
                'email' => $g->pick(['Y', 'N']),
            ];
            $data['audit_log'][] = [
                'ip' => sprintf('%d.%d.%d.%d', $g->r(11, 223), $g->r(0, 255), $g->r(0, 255), $g->r(1, 254)),
                'user_agent' => 'Mozilla/5.0 (X11; Linux x86_64) Test/' . $g->r(1, 99),
                'token' => $g->hex(64),
            ];
        }
        return ['tables' => $tables, 'rows' => $data];
    }

    private function next(): int
    {
        $this->x = ($this->x * 1103515245 + 12345) % 2147483648;
        return $this->x;
    }

    private function r(int $a, int $b): int
    {
        return $a + intdiv($this->next(), 7) % ($b - $a + 1);
    }

    private function pick(array $a): string
    {
        return (string) $a[$this->r(0, count($a) - 1)];
    }

    private function ssnArea(): int
    {
        do {
            $a = $this->r(1, 899);
        } while ($a === 666);
        return $a;
    }

    private function hex(int $n): string
    {
        $s = '';
        for ($i = 0; $i < $n; $i++) {
            $s .= dechex($this->r(0, 15));
        }
        return $s;
    }

    private function card(): string
    {
        $p = '4' . str_pad((string) $this->r(0, 99999), 5, '0', STR_PAD_LEFT) . str_pad((string) $this->r(0, 999999999), 9, '0', STR_PAD_LEFT);
        $sum = 0;
        $alt = true;
        for ($i = strlen($p) - 1; $i >= 0; $i--) {
            $d = (int) $p[$i];
            if ($alt) {
                $d *= 2;
                if ($d > 9) {
                    $d -= 9;
                }
            }
            $sum += $d;
            $alt = !$alt;
        }
        return $p . ((10 - $sum % 10) % 10);
    }

    private function prose(?string $email): string
    {
        $w = [];
        for ($i = 0, $n = $this->r(8, 16); $i < $n; $i++) {
            $w[] = $this->pick(self::WORDS);
        }
        return ucfirst(implode(' ', $w)) . '.' . ($email !== null ? ' Contact ' . $email . ' after 5pm.' : '');
    }
}
