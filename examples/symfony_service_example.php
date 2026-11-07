<?php

declare(strict_types=1);

/**
 * Service Symfony 8.1 / PHP 8.4+ intégrant des fonctions natives IFA via FFI Zero-Copy.
 *
 * Utilise la bibliothèque partagée compilée en IFA (zero-GC, deterministic) avec gestion
 * du cycle de vie des requêtes via arène générationnelle et ResetInterface.
 */

namespace App\Service;

use FFI;
use RuntimeException;
use Symfony\Contracts\Service\ResetInterface;

class IfaNativeBridgeService implements ResetInterface
{
    private ?FFI $ffi = null;
    private ?int $currentArenaId = null;

    public function __construct(
        string $libraryPath,
        ?string $headerPath = null,
        bool $autoArena = true,
    ) {
        if (file_exists($libraryPath)) {
            $cdef = <<< 'CDEF_BLOCK'
typedef long int64_t;
typedef unsigned long uint64_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef _Bool bool;

typedef struct {
    const char* ptr;
    size_t len;
} ifa_slice_t;

typedef struct {
    char* ptr;
    size_t len;
    size_t cap;
} ifa_mut_slice_t;

uint16_t ifa_rt_arena_create(size_t capacity);
void ifa_rt_arena_reset(uint16_t arena_id);
void ifa_rt_arena_destroy(uint16_t arena_id);
void* ifa_rt_arena_alloc(uint16_t arena_id, size_t size, size_t align);
ifa_slice_t ifa_rt_slice_from_raw(const char* ptr, size_t len);
ifa_mut_slice_t ifa_rt_slice_alloc(size_t len, uint16_t arena_id);
void ifa_rt_slice_free(ifa_mut_slice_t slice);
const char* ifa_rt_version_string(void);

uint64_t ifa_fast_hash(uint64_t seed, uint64_t iterations);
int64_t ifa_batch_sum(int64_t base, int64_t count);
CDEF_BLOCK;

            $this->ffi = FFI::cdef($cdef, $libraryPath);

            if ($autoArena) {
                $this->currentArenaId = (int) $this->ffi->ifa_rt_arena_create(65536);
            }
        }
    }

    public function __destruct()
    {
        if ($this->currentArenaId !== null && $this->ffi !== null) {
            try {
                $this->ffi->ifa_rt_arena_destroy($this->currentArenaId);
            } catch (\Throwable) {
                // Nettoyage silencieux
            }
            $this->currentArenaId = null;
        }
    }

    public function isAvailable(): bool
    {
        return $this->ffi !== null;
    }

    /**
     * Hook Symfony ResetInterface : recyclage de l'arène générationnelle en O(1)
     * à la fin de chaque requête HTTP ou message de worker Messenger.
     */
    public function reset(): void
    {
        if ($this->currentArenaId !== null && $this->ffi !== null) {
            $this->ffi->ifa_rt_arena_reset($this->currentArenaId);
        }
    }

    /**
     * Création d'une tranche de mémoire immutable zero-copy référençant directement une chaîne PHP.
     */
    public function createSlice(string &$data): \FFI\CData
    {
        $this->ensureAvailable();
        return $this->ffi->ifa_rt_slice_from_raw($data, strlen($data));
    }

    /**
     * Lecture d'une tranche de mémoire native vers une chaîne PHP.
     */
    public function readSlice(\FFI\CData $slice): string
    {
        if ($slice->ptr === null || $slice->len === 0) {
            return '';
        }
        return FFI::string($slice->ptr, (int) $slice->len);
    }

    /**
     * Calcul de hachage ultra-rapide sans surcharge Garbage Collector PHP.
     */
    public function computeFastHash(int $seed, int $iterations): int
    {
        $this->ensureAvailable();
        return (int) $this->ffi->ifa_fast_hash($seed, $iterations);
    }

    /**
     * Agrégation en lot de haute intensité.
     */
    public function batchSum(int $base, int $count): int
    {
        $this->ensureAvailable();
        return (int) $this->ffi->ifa_batch_sum($base, $count);
    }

    private function ensureAvailable(): void
    {
        if ($this->ffi === null) {
            throw new RuntimeException("IFA Native runtime is not initialized.");
        }
    }
}
