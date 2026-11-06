<?php

declare(strict_types=1);

/**
 * Service Symfony 8.1 / PHP 8.4+ intégrant des fonctions natives IFA via FFI.
 *
 * Utilise la bibliothèque partagée compilée en IFA (zero-GC, deterministic).
 */
namespace App\Service;

use FFI;

class IfaNativeBridgeService
{
    private ?FFI $ffi = null;

    public function __construct(string $libraryPath, string $headerPath)
    {
        if (file_exists($libraryPath) && file_exists($headerPath)) {
            $headerContent = file_get_contents($headerPath);
            $this->ffi = FFI::cdef($headerContent, $libraryPath);
        }
    }

    public function isAvailable(): bool
    {
        return $this->ffi !== null;
    }

    /**
     * Calcul de hachage ultra-rapide sans surcharge Garbage Collector PHP.
     */
    public function computeFastHash(int $seed, int $iterations): int
    {
        if ($this->ffi === null) {
            throw new \RuntimeException("IFA Native runtime is not initialized.");
        }

        return (int) $this->ffi->ifa_fast_hash($seed, $iterations);
    }

    /**
     * Agrégation en lot de haute intensité.
     */
    public function batchSum(int $base, int $count): int
    {
        if ($this->ffi === null) {
            throw new \RuntimeException("IFA Native runtime is not initialized.");
        }

        return (int) $this->ffi->ifa_batch_sum($base, $count);
    }
}
