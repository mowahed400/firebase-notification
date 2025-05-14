<?php

namespace Waheed\FirebaseNotification\Exceptions;

use Exception;

class FirebaseConfigurationException extends Exception
{
    public static function missingServiceAccountKey(string $path): self
    {
        return new static("Firebase service account key not found at: {$path}");
    }

    public static function invalidJsonInKeyFile(): self
    {
        return new static("Invalid JSON in service account key file");
    }
}
