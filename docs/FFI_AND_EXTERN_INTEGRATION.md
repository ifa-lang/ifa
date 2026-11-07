# Guide Technique : Intégration de Bibliothèques C et Rust via Kori et le Compilateur IFA

**Auteur :** ASSOGBA Prudence Dieudonné (@jprud67)  
**Langage :** IFA (ifa-lang/ifa)  
**Outil de Gestion de Paquets :** Kori (`kori.toml`, `kori.lock`)  
**Version de Référence :** v0.1.0 (série 0.1.*)

---

## 1. Introduction et Architecture FFI

Le langage de programmation IFA est conçu pour une intégration native de premier ordre avec l'écosystème C et Rust. Grâce à son absence de Garbage Collector et à sa disposition mémoire conforme à la norme C-ABI standard (System V AMD64 ABI sous Linux/macOS, MSVC ABI sous Windows), IFA peut :

1. **Consommer directement des bibliothèques C et Rust** (statiques `.a` ou dynamiques `.so`, `.dll`, `.dylib`) sans coût de conversion ou de marshalling.
2. **Exporter des fonctions haute performance et des bibliothèques partagées** utilisables directement par d'autres environnements de production (PHP 8.4+, Node.js, Python, Go, Rust, C++).

---

## 2. Table de Correspondance des Types (C, Rust, IFA)

| Type C standard | Type Rust | Type IFA | Taille / Alignement | Notes & Sémantique |
| :--- | :--- | :--- | :---: | :--- |
| `uint8_t` / `unsigned char` | `u8` | `u8` | 1 octet | Octet brut non signé |
| `int8_t` / `char` | `i8` | `i8` | 1 octet | Entier signé |
| `uint16_t` | `u16` | `u16` | 2 octets | Entier 16 bits non signé |
| `int16_t` | `i16` | `i16` | 2 octets | Entier 16 bits signé |
| `uint32_t` | `u32` | `u32` | 4 octets | Entier 32 bits non signé |
| `int32_t` | `i32` | `i32` | 4 octets | Entier 32 bits signé |
| `uint64_t` | `u64` | `u64` | 8 octets | Entier 64 bits non signé |
| `int64_t` | `i64` | `i64` | 8 octets | Entier 64 bits signé |
| `size_t` | `usize` | `usize` | 4 ou 8 octets | Pointeur machine non signé |
| `float` | `f32` | `f32` | 4 octets | Flottant simple précision IEEE 754 |
| `double` | `f64` | `f64` | 8 octets | Flottant double précision IEEE 754 |
| `bool` | `bool` | `bool` | 1 octet | Booléen (0 = faux, 1 = vrai) |
| `const T*` | `*const T` | `*const T` | Pointeur (8 o.) | Pointeur brut non mutable |
| `T*` | `*mut T` | `*mut T` | Pointeur (8 o.) | Pointeur brut mutable |
| `void*` | `*mut c_void` | `*mut u8` | Pointeur (8 o.) | Pointeur opaque générique |
| `struct { const T* data; size_t len; }` | `&[T]` | `Slice<T>` | 16 octets (fat ptr) | Vue continue contiguë |

---

## 3. Déclaration de Fonctions Externes (`extern "C"`) dans IFA

Pour appeler une fonction C ou Rust depuis IFA, on déclare la signature de la fonction avec la clause `extern "C"` :

```ifa
// Déclaration d'intrinsèques ou de fonctions bibliothèques C standard
extern "C" fn puts(s: *const u8) -> i32;
extern "C" fn malloc(size: usize) -> *mut u8;
extern "C" fn free(ptr: *mut u8);

// Déclaration de fonction cryptographique native tierce
extern "C" fn crypto_verify_hmac_sha256(
    payload: *const u8,
    payload_len: usize,
    key: *const u8,
    key_len: usize,
    out_tag: *mut u8
) -> i32;

pub fn main() {
    let message = "IFA Native C-ABI Invocation\0";
    puts(message.as_ptr());
}
```

---

## 4. Export de Fonctions IFA vers C/Rust (`pub extern "C" strict fn`)

Pour qu'une fonction IFA soit exportable dans une bibliothèque partagée (`.so` / `.dll`) et invocable depuis C, Rust ou PHP FFI :

```ifa
// Export strict sans allocation sur le tas pour une latence minimale
pub extern "C" strict fn ifa_compute_payment_checksum(
    payload: *const u8,
    len: usize,
    secret_key: u64
) -> u64 {
    mut checksum: u64 = secret_key;
    mut i: usize = 0;
    while i < len {
        unsafe {
            let byte_val = *payload.offset(i) as u64;
            checksum = checksum ^ (byte_val * 1099511628211);
        }
        i = i + 1;
    }
    return checksum;
}
```

---

## 5. Configuration du Manifeste `kori.toml`

Le fichier `kori.toml` pilote le packaging, la compilation et la génération automatique des en-têtes C et bindings PHP FFI.

```toml
[package]
name = "fintech_core"
version = "0.1.0"
edition = "2026"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]
license = "MIT OR Apache-2.0"
description = "Moteur de calcul de transactions et passerelle de paiement haute fréquence"

[targets]
[targets.lib]
name = "fintech_core"
path = "src/lib.ifa"
crate_types = ["cdylib", "staticlib", "ifalib"]

[profiles.dev]
backend = "cranelift"
opt_level = 0
debug_assertions = true

[profiles.release]
backend = "llvm"
opt_level = 3
lto = "thin"
strip_symbols = true

[ffi]
generate_c_headers = true
generate_php_binding = true
php_namespace = "App\\Bridge\\FintechCore"
php_class_name = "FintechCoreService"
output_dir = "bridge/generated"
```

---

## 6. Intégration d'une Crate Rust Tierce avec Kori

Pour encapsuler une bibliothèque Rust (par exemple un moteur de parsing ultra-rapide ou une bibliothèque de chiffrement matériel) :

### Étape 1 : Créer la crate Rust avec `crate-type = ["staticlib", "cdylib"]`

Dans le `Cargo.toml` de la crate Rust :

```toml
[package]
name = "rust_hasher"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib", "cdylib"]

[dependencies]
blake3 = "1.5"
```

Dans `src/lib.rs` de la crate Rust :

```rust
#[no_mangle]
pub unsafe extern "C" fn rust_blake3_hash(
    data: *const u8,
    len: usize,
    out_hash: *mut u8,
) -> i32 {
    if data.is_null() || out_hash.is_null() {
        return -1;
    }
    let slice = std::slice::from_raw_parts(data, len);
    let hash = blake3::hash(slice);
    std::ptr::copy_nonoverlapping(hash.as_bytes().as_ptr(), out_hash, 32);
    0
}
```

### Étape 2 : Lier la crate Rust dans le projet IFA

Dans le fichier source IFA (`src/main.ifa`) :

```ifa
extern "C" fn rust_blake3_hash(data: *const u8, len: usize, out_hash: *mut u8) -> i32;

pub fn main() {
    let payload = "Transactions Sécurisées IFA 2026";
    mut hash_buf = [0u8; 32];
    
    let res = rust_blake3_hash(payload.as_ptr(), payload.len(), hash_buf.as_mut_ptr());
    if res == 0 {
        println("Empreinte Blake3 calculée avec succès par la crate Rust tierce.");
    }
}
```

---

## 7. Pont FFI PHP 8.4+ Automatisé

La commande `kori ffi-gen` analyse les déclarations `pub extern "C"` et produit automatiquement :
1. L'en-tête C standard (`.h`).
2. La classe de service PHP 8.4+ typée pour l'intégration FFI.

### Génération automatique :
```bash
kori ffi-gen --target php
```

### Exemple de Classe PHP FFI Générée (`FintechCoreService.php`) :

```php
<?php

declare(strict_types=1);

namespace App\Bridge\FintechCore;

use FFI;
use RuntimeException;

final class FintechCoreService
{
    private static ?FFI $ffi = null;

    public function __construct(string $libraryPath = null)
    {
        if (self::$ffi === null) {
            $path = $libraryPath ?? __DIR__ . '/../../bin/libfintech_core.so';
            $header = file_get_contents(__DIR__ . '/fintech_core.h');
            self::$ffi = FFI::cdef($header, $path);
        }
    }

    public function computePaymentChecksum(string $payload, int $secretKey): int
    {
        $len = strlen($payload);
        return self::$ffi->ifa_compute_payment_checksum($payload, $len, $secretKey);
    }
}
```

---

## 8. Standards de Performance et Latence

- **Latence d'appel FFI IFA -> C / Rust :** 0 nanoseconde de surcoût (inlining d'appel direct via pointeur de fonction natif).
- **Latence d'appel PHP 8.4 -> IFA FFI :** ~40 à 60 nanosecondes par appel en environnement de production pré-chargé (`opcache.preload`).
- **Garantie de sûreté :** L'allocateur générationnel (`ifa-runtime`) et le mode `strict fn` garantissent l'absence absolue de corruption de mémoire, de double libération ou de dangling pointer lors des échanges entre langages.
