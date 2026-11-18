<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Masking\Enforcement\TableTarget;

/**
 * In a web request, TableTarget reads the schema from the service instance DreamFactory
 * created for the request (ServiceManager keeps it in its protected $services list) instead of
 * building another one; console processes and managers without that list build one as before.
 */
final class HandlingInstanceTest extends EnforcementHarness
{
    private function managerWithList(object $instance, bool $getServiceAllowed): object
    {
        $base = $this->app->make('df.service');
        // The service type's kind is decided (and cached) once, by building a sample service.
        $this->assertSame(\DreamFactory\Core\Masking\Enforcement\ServiceClass::COVERED, \DreamFactory\Core\Masking\Enforcement\ServiceClass::kindOf('crm'));

        return new class ($base, $instance, $getServiceAllowed) {
            protected $services = [];
            public int $built = 0;

            public function __construct(private $base, object $instance, private bool $allowed)
            {
                $this->services = ['crm' => $instance];
            }

            public function getService($name)
            {
                $this->built++;
                if (!$this->allowed) {
                    throw new \RuntimeException('getService() must not be called in a web request');
                }

                return $this->base->getService($name);
            }

            public function __call($method, $args)
            {
                return $this->base->{$method}(...$args);
            }
        };
    }

    /** Runs $call with app() answering runningInConsole() = $console (the harness container has no such method). */
    private function as(bool $console, \Closure $call): mixed
    {
        $app = new class ($console) extends \Illuminate\Container\Container {
            public function __construct(private bool $console)
            {
            }

            public function runningInConsole(): bool
            {
                return $this->console;
            }
        };
        foreach (['df.service', 'request', 'config'] as $id) {
            if ($this->app->bound($id)) {
                $app->instance($id, $this->app->make($id));
            }
        }
        \Illuminate\Container\Container::setInstance($app);
        try {
            return $call();
        } finally {
            \Illuminate\Container\Container::setInstance($this->app);
        }
    }

    public function testWebRequestsReuseTheHandlingInstance(): void
    {
        $instance = $this->app->make('df.service')->getService('crm');
        $manager = $this->managerWithList($instance, false);
        $this->app->instance('df.service', $manager);
        TableTarget::forget();
        $target = $this->as(false, fn () => TableTarget::resolve('crm', 'customers'));
        $this->assertNotNull($target);
        $this->assertArrayHasKey('ssn', $target->fields);
        $this->assertSame(0, $manager->built);
    }

    public function testConsoleProcessesBuildAFreshInstance(): void
    {
        $instance = $this->app->make('df.service')->getService('crm');
        $manager = $this->managerWithList($instance, true);
        $this->app->instance('df.service', $manager);
        TableTarget::forget();
        $this->assertNotNull($this->as(true, fn () => TableTarget::resolve('crm', 'customers')));
        $this->assertSame(1, $manager->built);
    }

    public function testManagersWithoutTheListStillWork(): void
    {
        TableTarget::forget();
        $this->assertNotNull($this->as(false, fn () => TableTarget::resolve('crm', 'customers')), 'the harness manager has no $services list');
    }
}
