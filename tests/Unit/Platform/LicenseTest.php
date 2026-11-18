<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Platform;

use DreamFactory\Core\Components\InternalServiceRequest;
use DreamFactory\Core\Enums\LicenseLevel;
use DreamFactory\Core\Masking\Resources\DataMasking;
use DreamFactory\Core\Masking\Resources\SecurityBaseline;
use DreamFactory\Core\Masking\Support\License;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Data Masking and Compliance baselines need a Gold license level, as df-compliance's service
 * reports and restricted admins do: the level comes from DreamFactory's Environment (the highest
 * subscription_required of the installed service types).
 */
final class LicenseTest extends TestCase
{
    use ActsAsCaller;

    protected function setUp(): void
    {
        parent::setUp();
        $this->bootHarness();
        $this->db()->table('user')->insert([
            ['id' => 1, 'name' => 'Alex Admin', 'email' => 'k@example.com', 'is_sys_admin' => true],
            ['id' => 4, 'name' => 'App User', 'email' => 'u@example.com', 'is_sys_admin' => false],
        ]);
        $this->actAs(1);
    }

    protected function tearDown(): void
    {
        License::resolveUsing(static fn () => LicenseLevel::GOLD);
        parent::tearDown();
    }

    /** @param list<string|null> $levels subscription_required of the installed service types */
    private function installServiceTypes(array $levels): void
    {
        if (!class_exists('ServiceManager', false)) {
            class_alias(\DreamFactory\Core\Facades\ServiceManager::class, 'ServiceManager');
        }
        $types = array_map(static fn (?string $level) => new class ($level) {
            public function __construct(private ?string $level)
            {
            }

            public function subscriptionRequired(): ?string
            {
                return $this->level;
            }
        }, $levels);
        $this->app->instance('df.service', new class ($types) {
            public function __construct(private array $types)
            {
            }

            public function getServiceTypes(): array
            {
                return $this->types;
            }
        });
        \Illuminate\Support\Facades\Facade::clearResolvedInstance('df.service');
        License::resolveUsing(null);
    }

    public static function installs(): array
    {
        return [
            'open source' => [[null, null], false],
            'silver' => [[null, LicenseLevel::SILVER], false],
            'gold' => [[null, LicenseLevel::SILVER, LicenseLevel::GOLD], true],
        ];
    }

    #[DataProvider('installs')]
    public function testTheLicenseLevelComesFromTheInstalledServiceTypes(array $levels, bool $gold): void
    {
        $this->installServiceTypes($levels);
        $this->assertSame($gold, License::isGold());
    }

    public function testALevelThatCannotBeReadIsNotGold(): void
    {
        License::resolveUsing(static fn () => throw new \RuntimeException('no service manager'));
        $this->assertFalse(License::isGold());
    }

    public function testTheSettingsApiNeedsGold(): void
    {
        $this->installServiceTypes([null, LicenseLevel::SILVER]);

        foreach ([['GET', '', []], ['GET', 'access', []], ['PATCH', '', ['mode' => 'preview']], ['POST', 'scan', []],
                  ['PATCH', 'mask', ['resource' => [['class' => 'email', 'format' => 'redact']]]]] as [$verb, $path, $payload]) {
            [$status, $body] = $this->call(new DataMasking(['name' => 'data_masking']), $verb, $path, $payload);
            $this->assertSame(403, $status, "$verb $path");
            $this->assertSame(License::MESSAGE, $body['error']['message'], "$verb $path");
        }
        $this->assertSame('off', Settings::mode(), 'nothing changed');
        $this->assertSame([], $this->db()->table(Tables::MASK_FORMAT)->get()->all());

        $this->installServiceTypes([LicenseLevel::GOLD]);
        $this->assertSame(200, $this->call(new DataMasking(['name' => 'data_masking']), 'GET', '')[0]);
    }

    public function testTheBaselinesApiNeedsGold(): void
    {
        License::resolveUsing(static fn () => LicenseLevel::OPEN_SOURCE);
        [$status, $body] = $this->call(new SecurityBaseline(['name' => 'security_baseline']), 'GET', '');
        $this->assertSame(403, $status);
        $this->assertSame(License::BASELINES_MESSAGE, $body['error']['message']);

        License::resolveUsing(static fn () => LicenseLevel::GOLD);
        $this->assertSame(200, $this->call(new SecurityBaseline(['name' => 'security_baseline']), 'GET', '')[0]);
    }

    public function testCallersWhoAreNotSysAdminsStillGetTheSysAdminAnswer(): void
    {
        License::resolveUsing(static fn () => LicenseLevel::OPEN_SOURCE);
        $this->actAs(4, false, 1);
        [$status, $body] = $this->call(new DataMasking(['name' => 'data_masking']), 'GET', '');
        $this->assertSame(403, $status);
        $this->assertSame('Only a system administrator can view Data Masking settings.', $body['error']['message']);
    }

    /** @return array{0:int,1:mixed} */
    private function call(object $resource, string $verb, string $path, array $payload = []): array
    {
        $request = new InternalServiceRequest();
        $request->setMethod($verb);
        $request->setPayloadData($payload);
        $response = $resource->handleRequest($request, $path);

        return [$response->getStatusCode(), $response->getContent()];
    }
}
