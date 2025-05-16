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
        $this->keyPath = config('firebase.service_account_key_path');
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
        ];

        if (isset($notificationData['image'])) {
            $message['notification']['image'] = $notificationData['image'];
        }

        return $this->sendRequest(['message' => $message]);
    }

    public function sendToTopic(string $topic, array $data): array|null
    {
        $accessToken = $this->getTopicToken();

        if (!$accessToken) {
            return null;
        }

        $payload = [
            'message' => [
                'topic' => $topic,
                'notification' => [
                    'title' => $data['title'] ?? '',
                    'body' => $data['body'] ?? '',
                ],
                'data' => $data['data'] ?? [],
                'webpush' => [
                    'notification' => [
                        'icon' => $data['icon'] ?? '',
                        'click_action' => $data['link'] ?? '',
                        'sound' => $data['sound'] ?? 'default',
                    ]
                ]
            ]
        ];

        $url = 'https://fcm.googleapis.com/v1/projects/' . $this->projectId . '/messages:send';

        $response = Http::withToken($accessToken)
            ->withHeaders(['Content-Type' => 'application/json'])
            ->post($url, $payload);

        return $response->json();
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
        ];

        return $this->sendRequest(['message' => $message]);
    }


    public function subscribeToTopic(array $fcmTokens, string $topic): array|null
    {
        $accessToken = $this->getTopicToken();

        if (!$accessToken) {
            return null;
        }

        $url = "https://iid.googleapis.com/v1:batchAdd";
        $payload = [
            'to' => "/topics/{$topic}",
            'registration_tokens' => $fcmTokens,
        ];

        $response = Http::withToken($accessToken)
            ->withHeaders(['Content-Type' => 'application/json'])
            ->post($url, $payload);

        return $response->json();
    }


    public function unsubscribeFromTopic(array $fcmTokens, string $topic): array|null
    {
        $accessToken = $this->getTopicToken();

        if (!$accessToken) {
            return null;
        }

        $url = "https://iid.googleapis.com/v1:batchRemove";
        $payload = [
            'to' => "/topics/{$topic}",
            'registration_tokens' => $fcmTokens,
        ];

        $response = Http::withToken($accessToken)
            ->withHeaders(['Content-Type' => 'application/json'])
            ->post($url, $payload);

        return $response->json();
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
            'priority' => $notificationData['priority'] ?? $this->defaultConfig['priority'],
            'ttl' => $notificationData['time_to_live'] ?? $this->defaultConfig['time_to_live'] . 's',
        ];
    }

    protected function buildApnsPayload(array $notificationData): array
    {
        return [
            'payload' => [
                'aps' => [
                    'sound' => $notificationData['sound'] ?? $this->defaultConfig['sound'],
                    'link' => $notificationData['link'] ?? $this->defaultConfig['link'],
                    'badge' => $notificationData['badge'] ?? 1,
                ]
            ],
            'headers' => [
                'apns-priority' => $notificationData['priority'] === 'high' ? '10' : '5',
            ]
        ];
    }

    protected function buildWebPushPayload(array $notificationData): array
    {
        return [
            'notification' => [
                'icon' => $notificationData['icon'] ?? '',
                'badge' => $notificationData['badge'] ?? '',
                'data' => [
                    'link' => $notificationData['link'] ?? $this->defaultConfig['link'],
                ]
            ]
        ];
    }

    protected function buildFcmOptions(array $notificationData): array
    {
        return [
            'analytics_label' => $notificationData['analytics_label'] ?? '',
            'link' => $notificationData['link'] ?? $this->defaultConfig['link'],
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

    public function getTopicToken()
    {
        try {
            // Use the configured key path instead of hardcoded path
            if (!file_exists($this->keyPath)) {
                Log::channel('firebase')->error('FCM Key File Missing');
                return null;
            }

            $keyData = json_decode(file_get_contents($this->keyPath), true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                Log::channel('firebase')->error('FCM Key JSON Invalid');
                return null;
            }

            $header = ['alg' => 'RS256', 'typ' => 'JWT'];
            $now = time();
            $claims = [
                'iss' => $keyData['client_email'],
                'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
                'aud' => 'https://oauth2.googleapis.com/token',
                'exp' => $now + 3600,
                'iat' => $now
            ];

            $jwt = $this->generateJWT($header, $claims, $keyData['private_key']);
            $response = $this->fetchAuthToken($jwt);

            if (isset($response['access_token'])) {
                return $response['access_token'];
            } else {
                Log::channel('firebase')->error('FCM Topic Token Error: Invalid token response', ['response' => $response]);
                return null;
            }
        } catch (\Exception $e) {
            Log::channel('firebase')->error('FCM Topic Token Error', ['error' => $e->getMessage()]);
            return null;
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
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_CAINFO => storage_path('certs/cacert.pem'),
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
