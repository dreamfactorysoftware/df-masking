<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Components\InternalServiceRequest;
use DreamFactory\Core\Events\ApiEvent;
use DreamFactory\Core\Events\PostProcessApiEvent;
use DreamFactory\Core\Events\PreProcessApiEvent;
use DreamFactory\Core\Exceptions\InternalServerErrorException;
use DreamFactory\Core\Masking\Enforcement\Listener;
use DreamFactory\Core\Masking\Enforcement\Policy;
use DreamFactory\Core\Masking\Enforcement\TableTarget;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Utility\ServiceResponse;

/**
 * In Preview, a policy store that cannot be read (dm_column renamed
 * or dropped, or every dm_* table gone while the settings are still cached) answered every
 * covered-table request with 500. Preview only reports: the request and response pass through
 * unchanged. Mode On keeps failing closed.
 *
 * Related records hidden by a masked join key are fetched by an internal
 * request; its filter:<col> decision now reaches the outer response's Rewrites header.
 */
final class PreviewAndCollectorTest extends EnforcementHarness
{
    private function breakPolicyStore(): void
    {
        $this->db()->getSchemaBuilder()->rename(Tables::COLUMN, 'dm_column_hidden');
        // A new request: per-process memos are empty; cached policy entries were keyed by an older version.
        PolicyVersion::bump();
        Settings::flush();
        Policy::forget();
        TableTarget::forget();
    }

    public function testPreviewPassesRequestsThroughWhenThePolicyCannotBeRead(): void
    {
        Settings::set('mode', 'preview');
        $this->breakPolicyStore();
        $this->assertSame('preview', Settings::mode());

        $request = $this->request('GET', ['fields' => '*', 'filter' => "ssn = '" . self::SSN . "'"]);
        $response = $this->tableFlow($request, new ServiceResponse(['resource' => [$this->record()]]), 'customers');

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(['resource' => [$this->record()]], $response->getContent(), 'Preview never changes data');
        $this->assertSame(['fields' => '*', 'filter' => "ssn = '" . self::SSN . "'"], $request->getParameters(), 'nor the request');
        $this->assertSame([], $response->getHeaders(), 'Preview adds no headers');
    }

    public function testModeOnStillFailsClosedWhenThePolicyCannotBeRead(): void
    {
        $this->breakPolicyStore();
        $this->assertSame('on', Settings::mode());
        $this->expectException(InternalServerErrorException::class);
        $this->tableFlow($this->request('GET', ['fields' => '*']), new ServiceResponse(['resource' => [$this->record()]]), 'customers');
    }

    /** migrate:reset (or a manual DROP) while Preview is cached: requests pass and the cache is dropped. */
    public function testPreviewWithEveryTableGoneStopsTrustingTheCachedSettings(): void
    {
        Settings::set('mode', 'preview');
        Settings::flush();
        $this->assertSame('preview', Settings::mode()); // cached under the current version
        foreach ([Tables::SCAN, 'dm_activity', 'dm_role_access', 'dm_admin_grant', 'dm_rule', 'dm_mask_format', Tables::COLUMN, Tables::SETTING, Tables::BASELINE] as $t) {
            $this->db()->getSchemaBuilder()->dropIfExists($t);
        }
        Settings::flush();
        Policy::forget();
        TableTarget::forget();
        $this->assertSame('preview', Settings::mode(), 'served from the cache');

        $response = $this->tableFlow($this->request('GET', ['fields' => '*']), new ServiceResponse(['resource' => [$this->record()]]), 'customers');
        $this->assertSame(['resource' => [$this->record()]], $response->getContent());

        Settings::flush();
        $this->assertSame('off', Settings::mode(), 'the tables are gone: not installed, nothing to enforce');
    }

    private function defineTax(): void
    {
        $this->defineTable('vf3_tax', [
            ['id', 'id', 'clear', null, null],
            ['tax_ssn', 'string', 'masked', 'national_id', 'restricted'],
            ['amount', 'string', 'clear', null, null],
        ]);
    }

    private function pre(InternalServiceRequest $request, string $table): void
    {
        $none = null;
        foreach (['crm._table.{table_name}', 'crm._table.' . $table] as $name) {
            $this->listener->onPreProcess(new PreProcessApiEvent($name, $request, $none, $table));
        }
    }

    private function post(InternalServiceRequest $request, ServiceResponse $response, string $table): void
    {
        foreach (['crm._table.{table_name}', 'crm._table.' . $table] as $name) {
            $this->listener->onPostProcess(new PostProcessApiEvent($name, $request, $response, $table));
        }
        foreach (['crm._table.{table_name}', 'crm._table.' . $table] as $name) {
            $this->listener->onFinal(new ApiEvent($name, $request, $response, $table));
        }
    }

    public function testRelatedRecordsHiddenByAMaskedJoinKeyAreReportedOnTheOuterResponse(): void
    {
        $this->defineTax();
        $outer = $this->request('GET', ['ids' => '1,2,3', 'fields' => 'id,ssn', 'related' => 'vf3_tax_by_ssn']);
        $this->pre($outer, 'customers');

        // DreamFactory fetches the related records with an internal request on the joined table.
        $inner = $this->request('GET', ['filter' => "(tax_ssn IN ('" . self::SSN . "','987-65-4321'))"]);
        $innerResponse = $this->tableFlow($inner, new ServiceResponse(['resource' => []]), 'vf3_tax');
        $this->assertSame('filter:tax_ssn', $innerResponse->getHeaders()[Listener::HEADER_REWRITES]);

        $response = new ServiceResponse(['resource' => [$this->record() + ['vf3_tax_by_ssn' => []]]]);
        $this->post($outer, $response, 'customers');
        $this->assertSame('filter:tax_ssn', $response->getHeaders()[Listener::HEADER_REWRITES] ?? null, 'the caller can tell related rows were withheld');
    }

    public function testOwnAndRelatedDroppedItemsAreMergedCappedAndEncoded(): void
    {
        $this->defineTax();
        $outer = $this->request('GET', ['fields' => '*', 'filter' => "ssn = 'x'", 'related' => 'vf3_tax_by_ssn']);
        $this->pre($outer, 'customers');
        $this->tableFlow($this->request('GET', ['filter' => "tax_ssn IN ('a')"]), new ServiceResponse(['resource' => []]), 'vf3_tax');
        $this->tableFlow($this->request('GET', ['filter' => "tax_ssn IN ('b')"]), new ServiceResponse(['resource' => []]), 'vf3_tax');
        $response = new ServiceResponse(['resource' => []]);
        $this->post($outer, $response, 'customers');
        $this->assertSame('filter:ssn, filter:tax_ssn', $response->getHeaders()[Listener::HEADER_REWRITES]);
    }

    public function testAnEarlierRequestsDroppedItemsAreNotReportedOnALaterOne(): void
    {
        $this->defineTax();
        $first = $this->tableFlow($this->request('GET', ['filter' => "tax_ssn = 'a'"]), new ServiceResponse(['resource' => []]), 'vf3_tax');
        $this->assertSame('filter:tax_ssn', $first->getHeaders()[Listener::HEADER_REWRITES]);

        $later = $this->tableFlow($this->request('GET', ['fields' => '*']), new ServiceResponse(['resource' => [$this->record()]]), 'customers');
        $this->assertArrayNotHasKey(Listener::HEADER_REWRITES, $later->getHeaders(), 'not nested in it: not reported');
    }
}
