<?php

namespace Mowahed\FirebaseNotification;

use Illuminate\Support\ServiceProvider;
use Mowahed\FirebaseNotification\Service\FirebaseNotificationService;

class FirebaseNotificationServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->publishes([
            __DIR__ . '/config/firebase.php' => config_path('firebase.php'),
            __DIR__ . '/config/logging.php' => config_path('logging.php'),
        ], 'firebase-config');

        $this->configureLogging();
    }

    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__ . '/config/firebase.php', 'firebase'
        );

        // Merge logging configuration without publishing
        $this->mergeConfigFrom(
            __DIR__ . '/config/logging.php', 'logging'
        );

        $this->app->singleton(FirebaseNotificationService::class, function ($app) {
            return new FirebaseNotificationService();
        });

        // Optional: For backward compatibility
        $this->app->alias(FirebaseNotificationService::class, 'firebase-notification');
    }

    protected function configureLogging(): void
    {
        // Only add the channel if it doesn't exist and if logging configuration is loaded
        if ($this->app['config']->has('logging.channels')) {
            $channels = $this->app['config']->get('logging.channels', []);

            if (!array_key_exists('firebase', $channels)) {
                $this->app['config']->set('logging.channels.firebase', [
                    'driver' => 'daily',
                    'path' => storage_path('logs/firebase.log'),
                    'level' => env('LOG_LEVEL', 'debug'),
                    'days' => 14,
                ]);
            }
        }
    }
}