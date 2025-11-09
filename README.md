# Firebase Notification Package for Laravel

A comprehensive Laravel package for sending Firebase Cloud Messaging (FCM) push notifications to devices, topics, and
conditions.

## Features

- Send notifications to individual devices
- Send notifications to topics
- Subscribe/unsubscribe devices from topics
- Send notifications based on conditions
- Comprehensive error logging
- Support for all FCM features (images, sounds, deep links, etc.)

## Installation

1. Install via Composer:

```bash
composer require mowahed/firebase-notification:^2.0.2

php artisan vendor:publish --tag=firebase-config

```

### Add This in .env

```dotenv
FIREBASE_PROJECT_ID="your-project-id"
FIREBASE_CREDENTIALS="app/firebase/service-account-key.json"
FIREBASE_LOGGING_ENABLED="true"
FIREBASE_LOGGING_CHANNEL="firebase"
```

## Add this in logging.php

```php

 'channels' => [
    'firebase' => [
        'driver' => 'single',
        'path' => storage_path('logs/firebase.log'),
        'level' => 'error',
    ],
],

```

## 2. Send Notification to Device

```php
use Mowahed\FirebaseNotification\Facades\FirebaseNotification;

$response = FirebaseNotification::sendToDevice('device_fcm_token', [
    'title' => 'Welcome!',
    'body' => 'Thanks for installing our app!',
    'link' => 'https://yourapp.com',
    'sound' => 'default',
    'image' => 'https://example.com/notification.png',
    'priority' => 'high'
]);
 ```

## 3. Send Notification to Topic

```php
FirebaseNotification::sendToTopic('news,' [
    'title' => 'Breaking News',
    'body' => 'Something big just happened!',
    'link' => 'https://yourapp.com/news',
    'sound' => 'default'
]);
```

## 4. Subscribe Device to Topic

```php
$response = FirebaseNotification::subscribeToTopic(
    ['device_token_1', 'device_token_2'],
    'news'
);
```

## 5. Send Notification to Condition

```php
$response = FirebaseNotification::sendToCondition(
    "'sports' in topics || 'news' in topics",
    [
        'title' => 'Sports News',
        'body' => 'Latest sports updates!',
        'link' => 'https://yourapp.com/sports'
    ]
);

```

## 6. Unsubscribe Device from Topic

```php
$response = FirebaseNotification::unsubscribeFromTopic(
    ['device_token_1', 'device_token_2'],
    'news'
);
```



