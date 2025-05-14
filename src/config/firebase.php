<?php

return [
    'project_id' => env('FIREBASE_PROJECT_ID'),
    
    'service_account_key_path' => env(
        'FIREBASE_CREDENTIALS', 
        storage_path('app/firebase/service-account-key.json')
    ),
    
    'logging' => [
        'enabled' => env('FIREBASE_LOGGING_ENABLED', true),
        'channel' => env('FIREBASE_LOGGING_CHANNEL', 'stack'),
    ],
    
    'http' => [
        'timeout' => env('FIREBASE_HTTP_TIMEOUT', 10),
        'retry' => [
            'attempts' => env('FIREBASE_RETRY_ATTEMPTS', 3),
            'delay' => env('FIREBASE_RETRY_DELAY', 100),
        ],
    ],
];
