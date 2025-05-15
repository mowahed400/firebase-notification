<?php

namespace Mowahed\FirebaseNotification;

use Illuminate\Support\ServiceProvider;
use Mowahed\FirebaseNotification\Services\FirebaseNotificationService;

class FirebaseNotificationServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/firebase.php' => config_path('firebase.php'),
        ], 'firebase-config');
    }

    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/firebase.php', 'firebase'
        );

        $this->app->singleton('firebase-notification', function ($app) {
            return new FirebaseNotificationService();
        });
    }
}