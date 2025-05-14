<?php

namespace Waheed\FirebaseNotification\Exceptions;

use Exception;

class FirebaseNotificationException extends Exception
{
    public static function failedToGetAccessToken(): self
    {
        return new static("Failed to obtain Firebase access token");
    }

    public static function curlError(string $message): self
    {
        return new static("CURL Error: {$message}");
    }
}
