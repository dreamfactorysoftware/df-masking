<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Platform;

use DreamFactory\Core\Enums\LicenseLevel;
use DreamFactory\Core\Masking\Resources\DataMasking;
use DreamFactory\Core\Masking\Resources\SecurityBaseline;
use DreamFactory\Core\Masking\ServiceProvider;
use DreamFactory\Core\Masking\Tests\TestCase;
use DreamFactory\Core\System\Components\SystemResourceManager;

/**
 * `data_masking` and `security_baseline` are registered as Gold system resources, like the other
 * commercial packages' resources (df-limits, df-compliance, df-aauth), so `GET /api/v2/system` and
 * the admin app label them Gold.
 */
final class SystemResourceTypeTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->bootHarness();
    }

    public function testResourcesAreRegisteredAsGold(): void
    {
        $df = new SystemResourceManager($this->app);
        $this->assertNull($df->getResourceType('data_masking'));
        $this->assertNull($df->getResourceType('security_baseline'));

        ServiceProvider::addSystemResourceTypes($df);

        foreach (['data_masking' => DataMasking::class, 'security_baseline' => SecurityBaseline::class] as $name => $class) {
            $type = $df->getResourceType($name);
            $this->assertNotNull($type, $name);
            $this->assertSame($class, $type->getClassName(), $name);
            $this->assertSame(LicenseLevel::GOLD, $type->subscriptionRequired(), $name);
            $this->assertSame(LicenseLevel::GOLD, $type->toArray()['subscription_required'], $name);
            $this->assertFalse($type->isSingleton(), $name);
            $this->assertFalse($type->isReadOnly(), $name);
        }
    }

    public function testRegisteringTwiceKeepsOneOfEach(): void
    {
        $df = new SystemResourceManager($this->app);
        ServiceProvider::addSystemResourceTypes($df);
        ServiceProvider::addSystemResourceTypes($df);

        $names = $df->getResourceTypeNames();
        $this->assertSame(1, count(array_keys($names, 'data_masking', true)));
        $this->assertSame(1, count(array_keys($names, 'security_baseline', true)));
    }
}
