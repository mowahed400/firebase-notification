<?php

namespace Mowahed\FirebaseNotification\Service;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use Mowahed\FirebaseNotification\Exceptions\FirebaseConfigurationException;
use Mowahed\FirebaseNotification\Exceptions\FirebaseNotificationException;

class FirebaseNotificationService
{
    protected string $url;
    protected string $projectId;
    protected string $keyPath;
    protected string $serverKey;
    protected array $defaultConfig;

    public function __construct()
    {
        $this->validateConfig();

        $this->projectId = config('firebase.project_id');
        $this->keyPath = storage_path(config('firebase.service_account_key_path'));
        $this->url = "https://fcm.googleapis.com/v1/projects/{$this->projectId}/messages:send";
        $this->serverKey = '';
        $this->defaultConfig = [
            'sound' => 'default',
            'open_with' => '',
            'link' => '',
            'priority' => 'high',
            'time_to_live' => 3600,
        ];
    }

    protected function validateConfig(): void
    {
        if (empty(config('firebase.project_id')) || empty(config('firebase.service_account_key_path'))) {
            throw new FirebaseConfigurationException('Firebase configuration is incomplete. Please check your config file.');
        }
    }

    public function sendToDevice(string $fcmToken, array $notificationData): array
    {
        $this->validateNotificationData($notificationData);
        $this->serverKey = $this->getToken();
        $this->validateServerKey();

        $message = [
            "token" => $fcmToken,
            "notification" => [
                "title" => $notificationData['title'],
                "body" => $notificationData['body'],
            ],
            'data' => $this->buildDataPayload($notificationData),
            'android' => $this->buildAndroidPayload($notificationData),
            'apns' => $this->buildApnsPayload($notificationData),
            'webpush' => $this->buildWebPushPayload($notificationData),
        ];

        if (isset($notificationData['image'])) {
            $message['notification']['image'] = $notificationData['image'];
        }

        return $this->sendRequest(['message' => $message]);
    }

    public function sendToTopic(string $topic, array $notificationData): array
    {
        $this->validateNotificationData($notificationData);
        $accessToken = $this->getToken();

        if (!$accessToken) {
            throw new FirebaseNotificationException('Failed to obtain Firebase access token');
        }

        $message = [
            'topic' => $topic,
            'notification' => [
                'title' => $notificationData['title'],
                'body' => $notificationData['body'],
            ],
            'data' => $this->buildDataPayload($notificationData),
            'android' => $this->buildAndroidPayload($notificationData),
            'apns' => $this->buildApnsPayload($notificationData),
            'webpush' => $this->buildWebPushPayload($notificationData),
        ];

        if (isset($notificationData['image'])) {
            $message['notification']['image'] = $notificationData['image'];
        }

        $payload = ['message' => $message];

        try {
            $response = Http::withToken($accessToken)
                ->withHeaders(['Content-Type' => 'application/json'])
                ->post($this->url, $payload);

            if ($response->failed()) {
                Log::channel('firebase')->error('FCM Topic Send Failed', [
                    'status' => $response->status(),
                    'response' => $response->json()
                ]);
                throw new FirebaseNotificationException('Failed to send topic notification: ' . $response->body());
            }

            return $response->json();
        } catch (\Exception $e) {
            Log::channel('firebase')->error('FCM Topic Send Error', ['error' => $e->getMessage()]);
            throw new FirebaseNotificationException('Failed to send topic notification: ' . $e->getMessage());
        }
    }

    public function sendToCondition(string $condition, array $notificationData): array
    {
        $this->validateNotificationData($notificationData);
        $this->serverKey = $this->getToken();
        $this->validateServerKey();

        $message = [
            'condition' => $condition,
            'notification' => [
                'title' => $notificationData['title'],
                'body' => $notificationData['body'],
            ],
            'data' => $this->buildDataPayload($notificationData),
            'android' => $this->buildAndroidPayload($notificationData),
            'apns' => $this->buildApnsPayload($notificationData),
            'webpush' => $this->buildWebPushPayload($notificationData),
        ];

        if (isset($notificationData['image'])) {
            $message['notification']['image'] = $notificationData['image'];
        }

        return $this->sendRequest(['message' => $message]);
    }

    /**
     * Validate an FCM token
     */
    public function validateToken(string $fcmToken): array
    {
        $accessToken = $this->getToken();

        try {
            // Use the Instance ID API to get token info
            $url = "https://iid.googleapis.com/iid/info/{$fcmToken}?details=true";

            $response = Http::withToken($accessToken)
                ->get($url);

            $result = $response->json();

            return [
                'valid' => $response->successful(),
                'status' => $response->status(),
                'info' => $result
            ];
        } catch (\Exception $e) {
            return [
                'valid' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Subscribe tokens to a topic using FCM Management API
     * Note: This uses the newer management API endpoint
     */
    public function subscribeToTopic(array $fcmTokens, string $topic): array
    {
        $accessToken = $this->getToken();

        if (!$accessToken) {
            throw new FirebaseNotificationException('Failed to obtain Firebase access token');
        }

        // New FCM Management API endpoint
        $url = "https://iid.googleapis.com/iid/v1:batchAdd";

        $payload = [
            'to' => "/topics/{$topic}",
            'registration_tokens' => $fcmTokens,
        ];

        try {
            $response = Http::withToken($accessToken)
                ->withHeaders([
                    'Content-Type' => 'application/json',
                    'access_token_auth' => 'true'
                ])
                ->post($url, $payload);

            // Get the response body
            $result = $response->json();

            // Log the full response for debugging
            Log::channel('firebase')->info('FCM Topic Subscribe Response', [
                'status' => $response->status(),
                'topic' => $topic,
                'token_count' => count($fcmTokens),
                'result' => $result
            ]);

            // Check if response indicates success
            if ($response->successful()) {
                // Check for errors in the response body
                if (isset($result['results'])) {
                    // Count successful subscriptions
                    $successCount = 0;
                    $errors = [];

                    foreach ($result['results'] as $index => $res) {
                        if (isset($res['error'])) {
                            $errors[] = [
                                'token_index' => $index,
                                'error' => $res['error']
                            ];
                        } else {
                            $successCount++;
                        }
                    }

                    if (!empty($errors)) {
                        Log::channel('firebase')->warning('FCM Topic Subscribe Partial Success', [
                            'topic' => $topic,
                            'success_count' => $successCount,
                            'error_count' => count($errors),
                            'errors' => $errors
                        ]);
                    }

                    return [
                        'success' => true,
                        'success_count' => $successCount,
                        'error_count' => count($errors),
                        'errors' => $errors,
                        'raw_response' => $result
                    ];
                }

                return [
                    'success' => true,
                    'raw_response' => $result
                ];
            }

            // If not successful, log and try alternative method
            Log::channel('firebase')->error('FCM Topic Subscribe Failed', [
                'status' => $response->status(),
                'response' => $result,
                'topic' => $topic
            ]);

            // Try alternative method using REST API
            return $this->subscribeToTopicAlternative($fcmTokens, $topic, $accessToken);

        } catch (\Exception $e) {
            Log::channel('firebase')->error('FCM Topic Subscribe Error', [
                'error' => $e->getMessage(),
                'topic' => $topic
            ]);
            throw new FirebaseNotificationException('Failed to subscribe to topic: ' . $e->getMessage());
        }
    }

    /**
     * Alternative method using FCM REST API for topic subscription
     * This method subscribes tokens one by one using the direct IID API
     */
    protected function subscribeToTopicAlternative(array $fcmTokens, string $topic, string $accessToken): array
    {
        $results = [];
        $successCount = 0;
        $errors = [];

        foreach ($fcmTokens as $index => $token) {
            try {
                // Direct subscription using IID API
                $url = "https://iid.googleapis.com/iid/v1/{$token}/rel/topics/{$topic}";

                $response = Http::withToken($accessToken)
                    ->withHeaders(['Content-Type' => 'application/json'])
                    ->post($url);

                if ($response->successful()) {
                    $successCount++;
                    $results[] = [
                        'token_index' => $index,
                        'success' => true
                    ];
                } else {
                    $errorInfo = $response->json();
                    $errors[] = [
                        'token_index' => $index,
                        'error' => $errorInfo['error'] ?? 'Unknown error',
                        'status' => $response->status()
                    ];
                    $results[] = [
                        'token_index' => $index,
                        'success' => false,
                        'error' => $errorInfo
                    ];
                }
            } catch (\Exception $e) {
                $errors[] = [
                    'token_index' => $index,
                    'error' => $e->getMessage()
                ];
                $results[] = [
                    'token_index' => $index,
                    'success' => false,
                    'error' => $e->getMessage()
                ];
            }
        }

        Log::channel('firebase')->info('FCM Alternative Topic Subscribe Results', [
            'topic' => $topic,
            'success_count' => $successCount,
            'error_count' => count($errors),
            'results' => $results
        ]);

        return [
            'success' => $successCount > 0,
            'success_count' => $successCount,
            'error_count' => count($errors),
            'errors' => $errors,
            'results' => $results
        ];
    }

    /**
     * Unsubscribe tokens from a topic
     */
    public function unsubscribeFromTopic(array $fcmTokens, string $topic): array
    {
        $accessToken = $this->getToken();

        if (!$accessToken) {
            throw new FirebaseNotificationException('Failed to obtain Firebase access token');
        }

        $url = "https://iid.googleapis.com/iid/v1:batchRemove";

        $payload = [
            'to' => "/topics/{$topic}",
            'registration_tokens' => $fcmTokens,
        ];

        try {
            $response = Http::withToken($accessToken)
                ->withHeaders([
                    'Content-Type' => 'application/json',
                    'access_token_auth' => 'true'
                ])
                ->post($url, $payload);

            $result = $response->json();

            // Log the full response for debugging
            Log::channel('firebase')->info('FCM Topic Unsubscribe Response', [
                'status' => $response->status(),
                'topic' => $topic,
                'token_count' => count($fcmTokens),
                'result' => $result
            ]);

            if ($response->successful()) {
                // Check for errors in the response body
                if (isset($result['results'])) {
                    $successCount = 0;
                    $errors = [];

                    foreach ($result['results'] as $index => $res) {
                        if (isset($res['error'])) {
                            $errors[] = [
                                'token_index' => $index,
                                'error' => $res['error']
                            ];
                        } else {
                            $successCount++;
                        }
                    }

                    if (!empty($errors)) {
                        Log::channel('firebase')->warning('FCM Topic Unsubscribe Partial Success', [
                            'topic' => $topic,
                            'success_count' => $successCount,
                            'error_count' => count($errors),
                            'errors' => $errors
                        ]);
                    }

                    return [
                        'success' => true,
                        'success_count' => $successCount,
                        'error_count' => count($errors),
                        'errors' => $errors,
                        'raw_response' => $result
                    ];
                }

                return [
                    'success' => true,
                    'raw_response' => $result
                ];
            }

            // If not successful
            Log::channel('firebase')->error('FCM Topic Unsubscribe Failed', [
                'status' => $response->status(),
                'response' => $result,
                'topic' => $topic
            ]);

            throw new FirebaseNotificationException('Failed to unsubscribe from topic: ' . ($result['error'] ?? 'Unknown error'));

        } catch (\Exception $e) {
            Log::channel('firebase')->error('FCM Topic Unsubscribe Error', [
                'error' => $e->getMessage(),
                'topic' => $topic
            ]);
            throw new FirebaseNotificationException('Failed to unsubscribe from topic: ' . $e->getMessage());
        }
    }

    protected function validateNotificationData(array $notificationData): void
    {
        $validator = Validator::make($notificationData, [
            'title' => 'required|string|max:255',
            'body' => 'required|string',
            'link' => 'nullable|url',
            'sound' => 'nullable|string',
            'open_with' => 'nullable|string|in:app,browser',
            'image' => 'nullable|url',
            'priority' => 'nullable|string|in:normal,high',
            'time_to_live' => 'nullable|integer|min:0',
        ]);

        if ($validator->fails()) {
            Log::channel('firebase')->error('Validation failed', $validator->errors()->toArray());
            throw new FirebaseNotificationException('Invalid notification data: ' . $validator->errors()->first());
        }
    }

    protected function validateServerKey(): void
    {
        if (empty($this->serverKey)) {
            Log::channel('firebase')->error('FCM Error: Missing access token');
            throw new FirebaseNotificationException('Missing Firebase access token');
        }
    }

    protected function buildDataPayload(array $notificationData): array
    {
        return [
            'title' => $notificationData['title'],
            'body' => $notificationData['body'],
            'created_at' => now()->toDateTimeString(),
            'open_with' => $notificationData['open_with'] ?? $this->defaultConfig['open_with'],
            'link' => $notificationData['link'] ?? $this->defaultConfig['link'],
            'sound' => $notificationData['sound'] ?? $this->defaultConfig['sound'],
        ];
    }

    protected function buildAndroidPayload(array $notificationData): array
    {
        return [
            'notification' => [
                'sound' => $notificationData['sound'] ?? $this->defaultConfig['sound'],
                'click_action' => $notificationData['link'] ?? $this->defaultConfig['link'],
            ],
            'priority' => strtoupper($notificationData['priority'] ?? $this->defaultConfig['priority']),
            'ttl' => ($notificationData['time_to_live'] ?? $this->defaultConfig['time_to_live']) . 's',
        ];
    }

    protected function buildApnsPayload(array $notificationData): array
    {
        $aps = [
            'sound' => $notificationData['sound'] ?? $this->defaultConfig['sound'],
            'badge' => $notificationData['badge'] ?? 1,
        ];

        // Add alert if you want custom notification on iOS
        if (isset($notificationData['title']) || isset($notificationData['body'])) {
            $aps['alert'] = [
                'title' => $notificationData['title'] ?? '',
                'body' => $notificationData['body'] ?? '',
            ];
        }

        $payload = [
            'payload' => [
                'aps' => $aps
            ],
            'headers' => [
                'apns-priority' => ($notificationData['priority'] ?? 'high') === 'high' ? '10' : '5',
            ]
        ];

        // Add custom data for handling links in iOS app
        if (!empty($notificationData['link'])) {
            $payload['payload']['link'] = $notificationData['link'];
        }

        // Add fcm_options only if analytics_label is provided
        if (isset($notificationData['analytics_label'])) {
            $payload['fcm_options'] = [
                'analytics_label' => $notificationData['analytics_label']
            ];
        }

        return $payload;
    }

    protected function buildWebPushPayload(array $notificationData): array
    {
        $webPush = [
            'notification' => [
                'icon' => $notificationData['icon'] ?? '',
                'badge' => $notificationData['badge'] ?? '',
            ]
        ];

        // Add fcm_options with link if provided
        if (!empty($notificationData['link'])) {
            $webPush['fcm_options'] = [
                'link' => $notificationData['link']
            ];
        }

        // Add analytics_label if provided
        if (isset($notificationData['analytics_label'])) {
            if (!isset($webPush['fcm_options'])) {
                $webPush['fcm_options'] = [];
            }
            $webPush['fcm_options']['analytics_label'] = $notificationData['analytics_label'];
        }

        return $webPush;
    }

    protected function buildFcmOptions(array $notificationData): array
    {
        return [
            'analytics_label' => $notificationData['analytics_label'] ?? '',
        ];
    }

    protected function sendRequest(array $payload): array
    {
        try {
            $response = $this->sendCurlRequest($this->url, [
                'Authorization: Bearer ' . $this->serverKey,
                'Content-Type: application/json',
            ], $payload);

            if (isset($response['error'])) {
                Log::channel('firebase')->error('FCM Error Response', $response);
                throw new FirebaseNotificationException($response['error']['message'] ?? 'Unknown FCM error');
            }

            return $response;
        } catch (\Exception $e) {
            Log::channel('firebase')->error('FCM Request Failed', [
                'error' => $e->getMessage(),
                'payload' => $payload
            ]);
            throw new FirebaseNotificationException('Failed to send FCM message: ' . $e->getMessage());
        }
    }

    protected function sendCurlRequest(string $url, array $headers, array $data): array
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_POSTFIELDS => json_encode($data),
            CURLOPT_TIMEOUT => 30,
        ]);

        $response = curl_exec($ch);
        $error = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($response === false) {
            Log::channel('firebase')->error('FCM CURL Error', ['error' => $error]);
            throw new FirebaseNotificationException('CURL request failed: ' . $error);
        }

        $decodedResponse = json_decode($response, true) ?? [];

        if ($httpCode >= 400) {
            Log::channel('firebase')->error('FCM HTTP Error', [
                'code' => $httpCode,
                'response' => $decodedResponse
            ]);
            throw new FirebaseNotificationException(
                $decodedResponse['error']['message'] ?? "FCM request failed with HTTP code $httpCode"
            );
        }

        return $decodedResponse;
    }

    protected function getToken(): string
    {
        if (!file_exists($this->keyPath)) {
            Log::channel('firebase')->error('FCM Key File Missing', ['path' => $this->keyPath]);
            throw new FirebaseConfigurationException('Firebase service account key file not found');
        }

        $keyData = json_decode(file_get_contents($this->keyPath), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            Log::channel('firebase')->error('FCM Key JSON Invalid', ['path' => $this->keyPath]);
            throw new FirebaseConfigurationException('Invalid Firebase service account key JSON');
        }

        $now = time();
        $claims = [
            'iss' => $keyData['client_email'],
            'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
            'aud' => 'https://oauth2.googleapis.com/token',
            'exp' => $now + 3600,
            'iat' => $now
        ];

        $jwt = $this->generateJWT(['alg' => 'RS256', 'typ' => 'JWT'], $claims, $keyData['private_key']);
        $response = $this->fetchAuthToken($jwt);

        if (empty($response['access_token'])) {
            Log::channel('firebase')->error('FCM Token Error', ['response' => $response]);
            throw new FirebaseNotificationException('Failed to obtain Firebase access token');
        }

        return $response['access_token'];
    }

    public function getTopicToken(): string
    {
        return $this->getToken();
    }

    protected function generateJWT(array $header, array $claims, string $privateKey): string
    {
        $base64UrlHeader = $this->base64UrlEncode(json_encode($header));
        $base64UrlClaims = $this->base64UrlEncode(json_encode($claims));
        $signatureInput = $base64UrlHeader . '.' . $base64UrlClaims;

        $signature = '';
        if (!openssl_sign($signatureInput, $signature, $privateKey, 'SHA256')) {
            throw new FirebaseConfigurationException('Failed to generate JWT signature');
        }

        return $signatureInput . '.' . $this->base64UrlEncode($signature);
    }

    protected function fetchAuthToken(string $jwt): array
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => 'https://oauth2.googleapis.com/token',
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion' => $jwt
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
            CURLOPT_TIMEOUT => 10,
        ]);

        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            Log::channel('firebase')->error('FCM OAuth CURL Error', ['error' => $error]);
            throw new FirebaseNotificationException('Failed to fetch auth token: ' . $error);
        }

        return json_decode($response, true) ?? [];
    }

    protected function base64UrlEncode(string $data): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }
}
