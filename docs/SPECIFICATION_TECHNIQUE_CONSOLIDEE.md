# Spécification Technique Consolidée — Langage de Programmation IFA

**Auteur & Architecte Principal :** ASSOGBA Prudence Dieudonné (@jprud67)  
**Date :** 6 novembre 2026  
**Version :** 0.1.0  
**Licence :** MIT OR Apache-2.0  
**Dépôt Officiel :** https://github.com/ifa-lang/ifa  
**Extension Source :** `.ifa`  
**Gestionnaire de Paquets :** `kori` (manifeste : `kori.toml`, verrouillage : `kori.lock`)  
**Compilateur & Outillage CLI :** `ifa`

---

## 1. Vision et Principes Fondamentaux

IFA est un langage de programmation système moderne conçu pour concilier la sûreté mémoire absolue, la performance native bare-metal, et une ergonomie de développement fluide, sans recourir à un Garbage Collector ni imposer la complexité cognitive d'un borrow checker à durées de vie explicites (`'a`).

### 1.1. Les Piliers d'Architecture

1. **Modèle Mémoire Hybride Déterministe :**
   - **Sémantique de Valeur Mutable :** Isolation stricte des valeurs, passage par projection in-place (`inout`) avec vérification statique de la loi d'exclusivité, et Copy-on-Write (CoW) implicite.
   - **Références Générationnelles 64-bit pour Graphes & Structures Récursives :** Chaque allocation heap souple est précédée d'un en-tête `GenHeader` de 64 bits (`generation_counter: u32`, `allocation_flags: u16`, `arena_id: u16`). Les références `GenRef` de 128 bits mémorisent la génération attendue.
   - **Élimination Statique par Dominance (Dominance Analysis) :** Le compilateur élimine statiquement 90 % à 100 % des vérifications sur les chemins dominés. Les vérifications résiduelles à l'exécution sont inlinées en une comparaison d'entiers 32 bits coûtant **1 cycle CPU cible**.

2. **Concurrence Incolore (Colorless Concurrency) :**
   - Aucune distinction syntaxique `async`/`await`.
   - Ordonnanceur M:N de fibres ultra-légères sans GC (`FiberScheduler`), avec exécution multithread native sur plateformes OS et boucle événementielle coopérative trampoline sous WebAssembly/WASI.
   - Ponts I/O non-bloquants transparents (`std::io`, sockets, fichiers, WASI streams).

3. **Métaprogrammation Compile-Time Pure (`comptime`) :**
   - Évaluation statique de code pur via une machine virtuelle bytecode (`ComptimeVM`), permettant la génération de code typé, la validation de schémas et la spécialisation sans coût runtime.

4. **Double Pipeline de Compilation :**
   - **Profil Développement (`ifa run` / `ifa build --dev`) :** Backend **Cranelift JIT/AOT** pour une compilation quasi-instantanée (< 500 ms).
   - **Profil Production (`ifa build --release`) :** Backend **LLVM** avec vectorisation agressive SIMD, inlining d'intrinsèques et Link-Time Optimization (LTO) cross-module (`thin` / `fat`).

---

## 2. Structure du Cargo Workspace

Le compilateur IFA est structuré en 16 crates modulaires et hautement découplés :

```
ifa/
├── Cargo.toml                      # Racine du Cargo Workspace (résolveur 2, v0.1.0)
├── crates/
│   ├── ifa-span/                   # Gestion des spans de fichiers sources et internement Lasso (Symbol)
│   ├── ifa-diagnostics/            # Moteur de diagnostics visuels et formatage d'erreurs (Ariadne)
│   ├── ifa-lexer/                  # Analyse lexicale zéro-copie (Logos)
│   ├── ifa-ast/                    # Arbre de Syntaxe Abstraite et sémantique formelle des nœuds
│   ├── ifa-parser/                 # Parseur descendant récursif & Pratt parser pour expressions
│   ├── ifa-sema/                   # Résolution de noms, typage HM, loi d'exclusivité inout, CoW
│   ├── ifa-comptime/               # Machine virtuelle bytecode d'évaluation statique compile-time
│   ├── ifa-fir/                    # Représentation Intermédiaire SSA (CFG, passes CoW, dominance)
│   ├── ifa-runtime/                # Allocateur slab 64-bit, ordonnanceur de fibres, ponts C-ABI & WASI
│   ├── ifa-codegen-cranelift/      # Moteur JIT in-memory et compilateur AOT natif Cranelift
│   ├── ifa-codegen-llvm/           # Émetteur LLVM IR optimisant avec vectorisation et LTO cross-module
│   ├── ifa-stdlib/                 # Bibliothèque standard : JSON, CSV, SHA-256, BLAKE3, HTTP
│   ├── ifa-lsp/                    # Serveur de langage natif (Language Server Protocol 3.17)
│   ├── ifa-wasm/                   # Outils WebAssembly/WASI : inspection et bundler TypeScript/React
│   ├── kori/                       # Gestionnaire de paquets déterministe, cache BLAKE3, générateur FFI PHP
│   └── ifa-cli/                    # Interface en ligne de commande unifiée (`ifa`)
└── docs/                           # Documentation technique et spécifications de référence
```

---

## 3. Modèle Mémoire et Vérification Générationnelle (1 Cycle CPU)

### 3.1. Structure Binaire de l'En-tête Générationnel

Chaque slot alloué par l'allocateur à dalles (`ifa_rt_gen_alloc`) est immédiatement précédé par un bloc mémoire aligné sur 8 octets :

```text
Offset Mémoire      Taille     Champ                   Rôle Technique
[-8 .. -5]          4 octets   generation_counter      Compteur incrémenté lors de chaque free/realloc
[-4 .. -3]          2 octets   allocation_flags        Drapeaux d'état (FLAG_ACTIVE=1, FLAG_PINNED=2, ...)
[-2 .. -1]          2 octets   arena_id                Identifiant de l'arène propriétaire
[0 .. +size]        N octets   Payload                 Données utilisateur de l'objet
```

### 3.2. Référence Générationnelle Enrichie (`GenRef`)

Une référence `ref` vers un objet générationnel est représentée par une structure fat-pointer de 128 bits :
- `ptr: *mut u8` (64 bits) : adresse directe du payload.
- `remembered_gen: u32` (32 bits) : génération mémorisée lors de la création de la référence.
- `arena_id: u16` (16 bits) : arène d'allocation.
- `_reserved: u16` (16 bits) : alignement.

### 3.3. Émission Inlinée de la Vérification Résiduelle (1 Cycle CPU)

Lorsque l'analyse de dominance (`DominanceAnalysis` dans `ifa-fir`) n'a pas pu éliminer statiquement la vérification :
- **En LLVM IR :**
  ```llvm
  ; Fast-path 1-cycle CPU inlined generation check
  define linkonce_odr void @ifa_rt_gen_check(ptr %ptr, i32 %remembered_gen) alwaysinline {
  entry:
    %hdr_ptr = getelementptr inbounds i8, ptr %ptr, i64 -8
    %actual_gen = load i32, ptr %hdr_ptr, align 4
    %match = icmp eq i32 %actual_gen, %remembered_gen
    br i1 %match, label %ok, label %uaf, !prof !0

  ok:
    ret void

  uaf:
    call void @ifa_rt_panic_uaf(ptr %ptr, i32 %remembered_gen, i32 %actual_gen)
    unreachable
  }

  !0 = !{!"branch_weights", i32 1048576, i32 1}
  ```
- **En Cranelift IR :**
  ```rust
  let actual_gen = builder.ins().load(types::I32, MemFlagsData::trusted(), ptr, -8);
  let expected_gen = builder.ins().iconst(types::I32, remembered_gen);
  let is_valid = builder.ins().icmp(IntCC::Equal, actual_gen, expected_gen);
  builder.ins().trapz(is_valid, TrapCode::unwrap_user(1));
  ```
Le processeur exécute le chemin nominal en **1 seul cycle CPU** (branchement conditionnel prédit pris en ligne droite sans stall du pipeline).

---

## 4. Concurrence Incolore et Exécution WebAssembly / WASI

### 4.1. Ordonnanceur Hybride `FiberScheduler`

- **Sur Plateformes OS Négociées (x86_64, aarch64) :** Ordonnancement M:N multithread avec pool de workers `std::thread`, vol de travail et canaux synchrones (`Channel<T>`).
- **Sur WebAssembly (`wasm32-wasip1`, `wasm32-unknown-unknown`) :** Ordonnancement événementiel coopératif par trampoline mono-thread. Les appels `ifa_rt_wasi_step()` et `ifa_rt_wasi_run_all()` drainent la file d'attente sans exiger de threads POSIX.
- **Ponts I/O Non-Bloquants :** `ifa_rt_wasi_read_nonblocking` et `ifa_rt_wasi_write_nonblocking` cèdent automatiquement le tour d'exécution de la fibre lors d'un `WouldBlock` sans bloquer le runtime hôte (Wasmtime, Wasmer, Node.js, V8).

---

## 5. Gestionnaire de Paquets `kori` et Pont FFI PHP 8.4+ / Symfony 8.1

### 5.1. Manifeste Déterministe `kori.toml`

```toml
[package]
name = "fintech_engine"
version = "0.1.0"
edition = "2026"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]

[dependencies]
ifa-stdlib = { path = "../ifa-stdlib" }

[build]
backend = "llvm"
opt_level = 3
lto = "thin"
strict = true

[target]
cdylib = true
wasi = true
```

### 5.2. Intégration FFI PHP 8.4+ / Symfony 8.1

Le générateur FFI intégré à `kori` génère automatiquement les classes PHP 8.4+ typées avec chargement natif OPcache (`opcache.preload`) :

```php
// FFI Helper généré automatiquement par `kori bridge php`
namespace App\Infrastructure\IFA;

use FFI;

final class NativeFintechEngine
{
    private static ?FFI $ffi = null;

    public static function init(string $libraryPath): void
    {
        if (self::$ffi === null) {
            self::$ffi = FFI::cdef(
                "int64_t calculate_tax(int64_t amount);",
                $libraryPath
            );
        }
    }

    public static function calculateTax(int $amount): int
    {
        return self::$ffi->calculate_tax($amount);
    }
}
```

---

## 6. Outillage Développeur et Commandes CLI

Le compilateur unifié `ifa` regroupe l'ensemble des commandes nécessaires au cycle de vie du code :

- `ifa new <nom>` : Initialise un nouveau projet avec `kori.toml` et `src/main.ifa`.
- `ifa run [source]` : Compile et exécute instantanément via le JIT Cranelift.
- `ifa build [source] [--release]` : Compile vers un binaire exécutable ou un fichier objet AOT via LLVM (LTO Thin/Fat).
- `ifa test [source]` : Découvre et exécute automatiquement les fonctions de test (`test_*`).
- `ifa bench [--iterations N] [--multithread] [--threads T]` : Exécute la suite de benchmarks automatisés mesurant le surcoût de la vérification générationnelle (1 cycle CPU cible) par rapport au C brut et à Rust, ainsi que la résistance aux contentions multithread face à mimalloc et jemalloc.
- `ifa fmt [--check]` : Formatage canonique des sources.
- `ifa lint [source]` : Analyse statique de conformité stylistique et de sûreté.
- `ifa lsp` : Lance le démon Language Server Protocol (LSP 3.17) sur stdio.
- `ifa wasm inspect <file.wasm>` : Inspection des sections, exports et conformité binaire WebAssembly.
- `ifa wasm bundle <module> <file.wasm> [--out-dir dir]` : Génère un paquet npm/browser avec wrappers JavaScript et définitions TypeScript `.d.ts`.
- `ifa wasm run <file.wasm> [-f function] [-- args]` : Exécute directement un module WebAssembly WASI ou une fonction exportée via Wasmtime/Wasmer.

---

## 7. Matrice des Cibles de Compilation et Sorties d'Artefacts

Le moteur d'orchestration `kori` supporte la génération simultanée et déterministe de multiples types d'artefacts déclarés dans la section `[targets.lib]` du fichier `kori.toml` :

| Type de Cible (`crate_types`) | Extension d'Artefact | Rôle Technique & Cas d'Usage | Outils Associés |
| :--- | :--- | :--- | :--- |
| `cdylib` | `lib{name}.so` / `.dll` | Bibliothèque dynamique C-ABI avec en-têtes C `.h` et ponts typés PHP 8.4+ / Symfony 8.1 | GCC, Clang, FFI |
| `staticlib` | `lib{name}.a` | Archive statique C-ABI pour édition de liens embarquée ou standalone | `ar`, `llvm-ar` |
| `wasm` | `{name}.wasm` | Binaire WebAssembly WASI standardisé bare-metal sans Garbage Collector | Clang wasm32, Wasmtime |
| `ifalib` | `{name}.ifalib` | Module canonique FIR SSA pour distribution et réutilisation directe dans l'écosystème IFA | `kori pack`, `kori resolver` |
| `wasm_bundle` | `{name}_wasm_bundle/` | Paquetage npm complet avec `package.json`, définitions TypeScript `.d.ts` et wrappers React / Web OS | `ifa wasm bundle` |

