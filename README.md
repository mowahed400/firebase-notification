# Firebase Notification Package for Laravel

A Laravel package for sending Firebase Cloud Messaging (FCM) push notifications to devices and topics.

---

## 1. Installation

```bash
composer require mowahed/firebase-notification

php artisan vendor:publish --tag=firebase-config
```

## 2. Send Notification to Device


```php
use Mowahed\FirebaseNotification\Facades\FirebaseNotification;

FirebaseNotification::sendToDevice('device_token', [
      'title' => 'Welcome!',
      'body' => 'Thanks for installing our app!',
      'link' => 'https://yourapp.com',
      'sound' => 'default'
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
- FirebaseNotification::subscribeToTopic('device_token', 'news');
```

## 5. Unsubscribe Device from Topic
```php
- FirebaseNotification::unsubscribeFromTopic('device_token', 'news');
```
