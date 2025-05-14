<?php

namespace Waheed\FirebaseNotification\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

class FirebaseNotificationService
{
    protected string $url;
    protected string $projectId;
    protected string $keyPath;
    protected string $serverKey;

    public function __construct()
    {
        $this->projectId = config('firebase.project_id');
        $this->keyPath = config('firebase.service_account_key_path');
        $this->url = "https://fcm.googleapis.com/v1/projects/{$this->projectId}/messages:send";
        $this->serverKey = '';
    }

    public function send(string $fcm_token, array $notificationData): bool|array
    {
        $validation = Validator::make($notificationData, [
            'title' => 'required|string',
            'body' => 'required|string',
            'link' => 'nullable|url',
            'sound' => 'nullable|string',
            'open_with' => 'nullable|string',
        ]);

        if ($validation->fails()) {
            Log::channel('firebase')->error('Validation failed', $validation->errors()->toArray());
            return false;
        }

        $this->serverKey = $this->getToken();
        if (!$this->serverKey) {
            Log::channel('firebase')->error('FCM Error: Missing access token');
            return false;
        }

        $data = [
            'message' => [
                "token" => $fcm_token,
                "notification" => [
                    "title" => $notificationData['title'],
                    "body" => $notificationData['body'],
                ],
                'data' => [
                    'title' => $notificationData['title'],
                    'body' => $notificationData['body'],
                    'created_at' => now(),
                    'open_with' => $notificationData['open_with'] ?? '',
                    'link' => $notificationData['link'] ?? '',
                    'sound' => $notificationData['sound'] ?? 'default',
                ],
                'android' => [
                    'notification' => [
                        'sound' => $notificationData['sound'] ?? 'default',
                        'click_action' => $notificationData['link'] ?? '',
                    ],
                ],
                'apns' => [
                    'payload' => [
                        'aps' => [
                            'sound' => $notificationData['sound'] ?? 'default',
                            'link' => $notificationData['link'] ?? '',
                        ]
                    ]
                ]
            ]
        ];

        return $this->sendCurlRequest($data);
    }

    public function sendToTopic(string $topic, array $notificationData): bool|array
    {
        $validation = Validator::make($notificationData, [
            'title' => 'required|string',
            'body' => 'required|string',
            'link' => 'nullable|url',
            'sound' => 'nullable|string',
            'open_with' => 'nullable|string',
        ]);

        if ($validation->fails()) {
            Log::channel('firebase')->error('Validation failed', $validation->errors()->toArray());
            return false;
        }

        $this->serverKey = $this->getTopicToken();
        if (!$this->serverKey) {
            Log::channel('firebase')->error('FCM Error: Missing access token');
            return false;
        }

        $payload = [
            'message' => [
                'topic' => $topic,
                'notification' => [
                    'title' => $notificationData['title'],
                    'body' => $notificationData['body'],
                ],
                'data' => [
                    'title' => $notificationData['title'],
                    'body' => $notificationData['body'],
                    'created_at' => now(),
                    'open_with' => $notificationData['open_with'] ?? '',
                    'link' => $notificationData['link'] ?? '',
                    'sound' => $notificationData['sound'] ?? 'default',
                ],
            ]
        ];

        return $this->sendCurlRequest($payload);
    }

    public function getTopicToken(): ?string
    {
        try {
            $keyFilePath = public_path('firebasekey_test.json');
            if (!file_exists($keyFilePath)) {
                Log::channel('firebase')->error('FCM Key File Missing');
                return null;
            }

            $keyData = json_decode(file_get_contents($keyFilePath), true);
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

            // Check if the response contains a valid access token
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

    protected function sendCurlRequest(array $payload): array|bool
    {
        $encodedData = json_encode($payload);

        $headers = [
            'Authorization: Bearer ' . $this->serverKey,
            'Content-Type: application/json',
        ];

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $this->url,
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_CAINFO => storage_path('certs/cacert.pem'),
            CURLOPT_POSTFIELDS => $encodedData,
        ]);

        $result = curl_exec($ch);

        if ($result === false) {
            Log::channel('firebase')->error('FCM CURL Error', ['error' => curl_error($ch)]);
            curl_close($ch);
            return false;
        }

        curl_close($ch);
        return json_decode($result, true);
    }

    protected function getToken(): ?string
    {
        if (!file_exists($this->keyPath)) {
            Log::channel('firebase')->error('FCM Key File Missing');
            return null;
        }

        $keyData = json_decode(file_get_contents($this->keyPath), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            Log::channel('firebase')->error('FCM Key JSON Invalid');
            return null;
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

        return $response['access_token'] ?? null;
    }

    protected function generateJWT(array $header, array $claims, string $privateKey): string
    {
        $base64UrlHeader = $this->base64UrlEncode(json_encode($header));
        $base64UrlClaims = $this->base64UrlEncode(json_encode($claims));
        $signatureInput = $base64UrlHeader . '.' . $base64UrlClaims;

        openssl_sign($signatureInput, $signature, $privateKey, 'SHA256');

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
        ]);

        $response = curl_exec($ch);
        if ($response === false) {
            Log::channel('firebase')->error('FCM OAuth CURL Error', ['error' => curl_error($ch)]);
            return [];
        }

        curl_close($ch);
        return json_decode($response, true) ?? [];
    }

    protected function base64UrlEncode(string $data): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }
}