<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Classifier;

use DreamFactory\Core\Masking\Classifier\ColumnMeta;
use DreamFactory\Core\Masking\Classifier\Engine;
use DreamFactory\Core\Masking\Classifier\Evidence;
use DreamFactory\Core\Masking\Classifier\Ruleset;
use DreamFactory\Core\Masking\Classifier\TableMeta;
use DreamFactory\Core\Masking\Masking\Masker;
use PHPUnit\Framework\TestCase;

/**
 * A column of IP lists ("unknown, 203.0.113.7", "198.51.100.4, 10.0.0.4") under an IP name
 * (x_forwarded_for) is reported as ip_address (review), not free text: its values contradict the
 * single-IP shape, but the only personal data in them are IP addresses. Before: review
 * free_text_pii. Columns with other spans, or without an IP name, stay free text.
 */
final class IpListTest extends TestCase
{
    private static function classify(string $column, callable $value): array
    {
        $t = new TableMeta('public', 'access_logs', 'access_logs', 'table', [
            new ColumnMeta('id', 'integer', 'integer', null, true),
            new ColumnMeta($column, 'character varying(120)', 'string', 120),
        ], ['id']);
        $rows = array_map(static fn ($i) => ['id' => (string) $i, $column => $value($i)], range(1, 40));
        $sample = ['rows' => $rows, 'ordered' => 'pk', 'error' => null, 'queries' => 1];

        return Ruleset::engine('2026-10-28')->classifyDatabase([$t], static fn () => $sample, Engine::MODE_HYBRID)['access_logs.' . $column];
    }

    private static function ipList(int $i): string
    {
        return $i % 2 ? "unknown, 203.0.113.$i" : "198.51.100.$i, 10.0.0.$i";
    }

    public function testIpListsUnderAnIpNameAreIpAddresses(): void
    {
        // Half the rows are plain IP lists (IP samples), half carry a non-IP token.
        $v = self::classify('x_forwarded_for', [self::class, 'ipList']);

        $this->assertSame(['ip_address', 'identity'], [$v['class'], $v['tier']]);
        $this->assertContains($v['verdict'], ['review', 'enforce'], 'masked or review, as scoring gives');
        $this->assertNotContains('ip_address', array_column($v['evidence']['runner_up'] ?? [], 'class'), 'not also listed as a runner-up');
        $r = Evidence::fromEngine($v, false, Ruleset::pack());
        $this->assertSame(['ip_address', 'identity'], [$r['class'], $r['tier']]);
    }

    /**
     * Lists made only of IP addresses, the usual x_forwarded_for
     * ("203.0.113.7, 198.51.100.4", 2-3 hops, nothing else) were classified clear (name points
     * only, score 30): no detector matched a whole value and no text surrounded the IPs. A value
     * that splits on commas / whitespace into 2+ valid IPs is now an IP sample.
     */
    public function testPlainIpListsUnderAnIpNameAreIpAddresses(): void
    {
        $constant = self::classify('x_forwarded_for', static fn ($i) => $i % 3 ? '203.0.113.7, 198.51.100.4' : '203.0.113.7, 198.51.100.4, 192.0.2.10');
        $this->assertSame('ip_address', $constant['class'], 'the verify repro (two distinct values) is not clear any more');
        $this->assertContains($constant['verdict'], ['review', 'enforce']);

        $varied = self::classify('x_forwarded_for', static fn ($i) => "203.0.113.$i, 198.51.100." . (200 - $i));
        $this->assertSame(['enforce', 'ip_address', 'identity'], [$varied['verdict'], $varied['class'], $varied['tier']]);

        $v6 = self::classify('client_ip', static fn ($i) => sprintf('2001:db8::%x 10.0.0.%d', $i + 4096, $i));
        $this->assertSame('ip_address', $v6['class'], 'whitespace-separated, IPv6 first');
    }

    public function testPlainIpListsWithoutAnIpNameStayUnclassified(): void
    {
        $hops = self::classify('hops', static fn ($i) => "203.0.113.$i, 198.51.100." . (200 - $i));
        $this->assertNotSame('ip_address', $hops['class'], 'no IP name: no new discovery from IP lists');
    }

    public function testIpListHead(): void
    {
        $this->assertSame('203.0.113.7', Engine::ipListHead('203.0.113.7, 198.51.100.4'));
        $this->assertSame('203.0.113.7', Engine::ipListHead(' 203.0.113.7,198.51.100.4 , 10.0.0.1 '));
        $this->assertSame('2001:db8::1', Engine::ipListHead("2001:db8::1\t10.0.0.4"));
        $this->assertNull(Engine::ipListHead('203.0.113.7'), 'one address is not a list');
        $this->assertNull(Engine::ipListHead('unknown, 203.0.113.7'), 'any other token: not a pure list');
        $this->assertNull(Engine::ipListHead('1.2.3.4.5, 1.2.3.4'), 'every part must be a valid IP');
        $this->assertNull(Engine::ipListHead('1.2, 3.4'));
        $this->assertNull(Engine::ipListHead('deadbeef, cafe'));
    }

    /** Span masking is kept: free text and never-scanned columns still mask every IP of a list. */
    public function testSpanMaskingStillMasksEveryIpOfAList(): void
    {
        $masked = (new Masker(str_repeat("\x03", 32)))->maskSpans('203.0.113.7, 198.51.100.4');
        $this->assertStringNotContainsString('203.0.113.7', $masked);
        $this->assertStringNotContainsString('198.51.100.4', $masked);
        $this->assertStringContainsString(',', $masked, 'only the addresses are replaced');
    }

    public function testOtherSpansOrNoIpNameStayFreeText(): void
    {
        $mixed = self::classify('x_forwarded_for', static fn ($i) => $i % 2 ? "unknown, 203.0.113.$i" : "contact ops$i@example.org");
        $this->assertSame('free_text_pii', $mixed['class'], 'an email among the spans: free text');

        $hops = self::classify('hops', [self::class, 'ipList']);
        $this->assertSame('free_text_pii', $hops['class'], 'no IP name: free text');
    }
}
