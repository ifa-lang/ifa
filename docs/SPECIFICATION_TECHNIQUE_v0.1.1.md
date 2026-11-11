# Spécification Technique — Langage de Programmation IFA v0.1.1

**Auteur & Architecte Principal :** ASSOGBA Prudence Dieudonné (@jprud67)  
**Date d'émission :** 11 novembre 2026  
**Version cible :** v0.1.1  
**Statut :** Approuvé & En cours de déploiement  
**Licence :** MIT OR Apache-2.0  
**Dépôts Officiels :**
- Compilateur et Outillage Système : https://github.com/ifa-lang/ifa
- Gestionnaire de Paquets Autonome : https://github.com/ifa-lang/kori

---

## 1. Contexte & Objectifs Stratégiques v0.1.1

La version **v0.1.0** a consolidé le cœur du langage IFA :
1. Déterminisme absolu et point fixe bit-à-bit certifié sur le triple bootstrap (`sha256(ifac-gen2) == sha256(ifac-gen3)`).
2. Modèle mémoire hybride sans ramasse-miettes (GC) et sans durées de vie manuelles (sémantique de valeur mutable `inout`, Copy-on-Write transparent, références générationnelles 64-bit avec fast-path 1 cycle CPU).
3. Concurrence incolore (fibres M:N légères, primitives I/O non-bloquantes unifiées).
4. Bibliothèque standard industrielle comprenant 10 modules majeurs (réseau, crypto BLAKE3/SHA-256, I/O, système de fichiers, processus, synchronisation, temps, collections, JSON, CSV).
5. Gestionnaire de paquets `kori` réécrit en syntaxe pure IFA, autonome et opérationnel.
6. Suite de tests unitaires et d'intégration validée à 100 % au vert en intégration continue.

La version **v0.1.1** étend l'écosystème IFA vers quatre horizons majeurs :
- **Axe 1 — WebAssembly Component Model (WASI 0.2 & WIT) :** Prise en charge native du Component Model Wasm, de l'ABI Canonique (Canonical ABI), des interfaces WIT standardisées (`wit-bindgen` pour IFA) et de la spécification WASI 0.2 (`wasi:cli`, `wasi:http`, `wasi:filesystem`, `wasi:io`).
- **Axe 2 — Outillage de Développement & Serveur de Langage LSP 3.17 :** Indexation sémantique workspace multi-fichiers, renommage sécurisé inter-fichiers (`textDocument/rename`), complétion et validation statique en direct des invariants `comptime`, indices de types en ligne (inlay hints) et modificateurs sémantiques fins.
- **Axe 3 — Bibliothèque Standard Haute Performance :** Moteur de base de données embarqué zéro-copie (`std/db`) à journalisation Write-Ahead Log (WAL), et analyseur de trames HTTP/1.1 & HTTP/2 vectorisé par instructions SIMD (`std/net/simd_parser`).
- **Axe 4 — Écosystème Kori & Distribution de Paquets :** Gestion native des espaces de travail multi-paquets (`kori workspace`), signature cryptographique des artefacts avec Ed25519/BLAKE3, et connecteurs de registre OCI/Wasm.

```
+---------------------------------------------------------------------------------------+
|                                IFA RUNTIME & COMPILER v0.1.1                          |
+---------------------------------------------------------------------------------------+
|  Frontend & Sémantique        |  Moteur Comptime & Invariants |  Code Generation & IR |
|  - Inout / CoW Static Pass   |  - ComptimeVM Bytecode        |  - Cranelift JIT/AOT   |
|  - Typage Algébrique HM       |  - Validation Invariants LSP  |  - LLVM 18 LTO & SIMD |
+-------------------------------+-------------------------------+-----------------------+
|  WebAssembly Component Model |  Serveur de Langage LSP 3.17  |  Bibliothèque Standard|
|  - Wasm Component Binary Enc  |  - Renommage Multi-Fichiers   |  - std/db (WAL Engine)|
|  - Canonical ABI / WIT Types  |  - Graphe de Références       |  - std/net/simd_parser|
|  - WASI 0.2 Services          |  - Inlay Hints & Diagnostics  |  - Fibres Incolores   |
+-------------------------------+-------------------------------+-----------------------+
|  Gestionnaire de Paquets Kori v0.1.1                                                  |
|  - Espaces de travail multi-paquets (kori workspace)                                 |
|  - Signatures Ed25519 & Vérification d'intégrité BLAKE3                               |
|  - Registre de composants OCI / Wasm                                                  |
+---------------------------------------------------------------------------------------+
```

---

## 2. WebAssembly Component Model (WASI 0.2 & WIT)

### 2.1. Principes et Spécification Binaire

Le WebAssembly Component Model (défini par le Wasm W3C Community Group et WASI Preview 2) formalise la composition sécurisée de composants WebAssembly isolés via des interfaces typées étanches.

IFA v0.1.1 introduit dans `crates/ifa-wasm` l'émetteur de composants conformes à la spécification binaire Component Model :
- En-tête binaire Component : magic `\0asm` suivi de la version de format `0x0001000d` (Wasm Component Layer 1).
- Sections spécialisées du Component :
  1. `core-module` (ID: 0) : modules WebAssembly standard encapsulés émis par Cranelift ou LLVM.
  2. `type` (ID: 1) : définitions de types d'interfaces (records, variants, lists, resources).
  3. `core-instance` (ID: 2) : instanciations internes des modules Wasm hôtes.
  4. `alias` (ID: 3) : projections d'exports internes ou externes.
  5. `canon` (ID: 4) : ponts Canonical ABI (`canon lift`, `canon lower`).
  6. `import` (ID: 5) : dépendances vers interfaces WASI 0.2 ou composants tiers.
  7. `export` (ID: 6) : fonctions et interfaces exposées au monde extérieur.

### 2.2. Correspondance des Types IFA avec l'ABI Canonique (Canonical ABI)

L'ABI Canonique standardise la représentation en mémoire linéaire des types de haut niveau :

| Type IFA                 | Représentation Canonical ABI          | Taille (octets) | Alignement |
|--------------------------|---------------------------------------|-----------------|------------|
| `bool`                   | Entier `i32` restreint à {0, 1}       | 1               | 1          |
| `u8` / `i8`              | Entier 8-bit                          | 1               | 1          |
| `u16` / `i16`            | Entier 16-bit                         | 2               | 2          |
| `u32` / `i32`            | Entier 32-bit                         | 4               | 4          |
| `u64` / `i64`            | Entier 64-bit                         | 8               | 8          |
| `f32` / `f64`            | Flottant IEEE-754                     | 4 / 8           | 4 / 8      |
| `string`                 | Paire `(ptr: u32, len: u32)` en UTF-8 | 8               | 4          |
| `[T]` (slice)            | Paire `(ptr: u32, len: u32)`          | 8               | 4          |
| `struct R { ... }`       | Champs ordonnés selon règles C-layout | Sum(fields) + P | Max(align) |
| `enum V { ... }`         | `discriminant: u8/u16/u32` + payload  | Max(cases) + D  | Max(align) |
| `option<T>`              | Tag `u8` (0=None, 1=Some) + T         | 1 + Pad + sz(T) | align(T)   |
| `result<T, E>`           | Tag `u8` (0=Ok, 1=Err) + max(T, E)    | 1 + Pad + sz    | max(align) |
| `borrow<R>` (ressource)  | Identifiant handle entier 32-bit      | 4               | 4          |
| `own<R>` (ressource)     | Identifiant handle 32-bit avec destructeur | 4          | 4          |

#### Gestion Déterministe de la Mémoire de Transfert (`cabi_realloc`)
Chaque composant IFA exporte la fonction canonique d'allocation déterministe :
```ifa
pub fn cabi_realloc(
    old_ptr: u32,
    old_size: u32,
    alignment: u32,
    new_size: u32
) -> u32 {
    ifa_rt_wasm_realloc(old_ptr, old_size, alignment, new_size)
}
```
L'allocateur runtime Wasm de IFA assure une réallocation zéro-fragmentation avec alignement garanti jusqu'à 64 octets.

### 2.3. Moteur WIT (Wasm Interface Type) pour IFA

Le sous-module `crates/ifa-wasm/src/wit/` comprend :
- `parser.rs` : Analyseur syntaxique de fichiers d'interfaces `.wit`.
- `codegen.rs` : Générateur bi-directionnel :
  - **IFA vers WIT :** Extraction automatique des interfaces publiques et types structurés pour générer le monde WIT (`world.wit`).
  - **WIT vers IFA :** Génération de stubs de liaison strictement typés avec vérification compile-time des contrats d'interfaces.

Exemple de spécification d'un monde WIT :
```wit
package ifa:service@0.2.0;

interface kv-store {
    record entry {
        key: string,
        val: list<u8>,
        version: u64,
    }

    get: func(key: string) -> option<entry>;
    set: func(key: string, val: list<u8>) -> result<_, string>;
    delete: func(key: string) -> bool;
}

world server {
    import wasi:logging/logging@0.2.0;
    export kv-store;
}
```

Traduction automatique en code natif IFA :
```ifa
// Généré automatiquement par ifa-wit-bindgen v0.1.1
import wasi:logging/logging@0.2.0;

pub struct Entry {
    pub key: string,
    pub val: [u8],
    pub version: u64,
}

pub interface KvStore {
    fn get(key: string) -> option<Entry>;
    fn set(key: string, val: [u8]) -> result<(), string>;
    fn delete(key: string) -> bool;
}
```

### 2.4. Intégration WASI 0.2 Preview 2

IFA v0.1.1 implémente les liaisons système WASI 0.2 dans `ifa-runtime` et `ifa-stdlib` :
- `wasi:cli/environment`, `wasi:cli/exit`, `wasi:cli/stdin`, `wasi:cli/stdout`, `wasi:cli/stderr`.
- `wasi:clocks/monotonic-clock`, `wasi:clocks/wall-clock`.
- `wasi:filesystem/types`, `wasi:filesystem/preopens`.
- `wasi:io/streams` (flux non-bloquants synchronisés avec les fibres IFA).
- `wasi:http/incoming-handler`, `wasi:http/outgoing-handler` (permettant aux microservices IFA de s'exécuter directement dans des runtimes Wasm serverless tels que Wasmtime, Spin ou Cloudflare Workers).

---

## 3. Serveur de Langage LSP 3.17 & Ergonomie Développeur

### 3.1. Indexation Sémantique Multi-Fichiers & Graphe de Dépendances

Le serveur de langage `ifa-lsp` passe d'une analyse mono-document à une indexation globale de l'espace de travail :
- `WorkspaceSymbolIndex` : Graphe des symboles indexant l'ensemble des fichiers `.ifa` de la racine du projet ou du workspace Kori.
- Mise à jour différentielle : Recalcul incrémental sur notification `textDocument/didChange` avec verrouillage en lecture/écriture sans blocage (`RwLock`).
- Résolution croisée des importations (`import module::symbol;`) avec gestion stricte de la visibilité (`pub`, visibilité de crate).

```
[Document A: math.ifa]                      [Document B: main.ifa]
pub struct Vector3 { x: f64, y: f64, z: f64 }   import math::Vector3;
pub fn dot(a: Vector3, b: Vector3) -> f64       let v = Vector3 { x: 1.0, ... };
        ^                                               ^
        |----------- Index Symbolique Global -----------|
                     - Définition exacte
                     - Toutes les références croisées
                     - Renommage atomique
```

### 3.2. Renommage Sémantique Inter-Fichiers (`textDocument/rename`)

Le gestionnaire de renommage valide les conditions préalables :
1. Vérification que le symbole cible est un identifiant utilisateur valide et non un mot-clé réservé.
2. Détection de conflits de noms (shadowing) dans les scopes récepteurs de tous les fichiers impactés.
3. Émission d'un `WorkspaceEdit` complet contenant les modifications textuelles pour chaque fichier ouvert ou présent sur disque.

Protocole de vérification :
```
Client -> textDocument/prepareRename(position)
Server -> Range du symbole (ou null si mot-clé/non renommable)

Client -> textDocument/rename(position, new_name)
Server -> Validation syntaxique & sémantique
       -> Parcours du graphe de références du workspace
       -> Production des TextEdits groupés par URI
       -> Réponse WorkspaceEdit { changes: { uri1: [...], uri2: [...] } }
```

### 3.3. Évaluation en Direct des Invariants `comptime`

IFA v0.1.1 introduit l'affichage dynamique des invariants compile-time directement dans l'éditeur :
- **Comptime Hover :** Le survol d'une fonction `comptime` ou d'une constante affiche sa valeur évaluée par la `ComptimeVM` avec le temps d'exécution statique (ex: `/* comptime value: 42 (evaluated in 12 µs) */`).
- **Validation statique des assertions :** Détection précoce des violations d'assertions `comptime assert(expr)` et surlignage sous forme de diagnostic LSP de niveau `Error` avant même le lancement de la compilation complète.
- **Inlay Hints enrichis :**
  - Types inférés pour les déclarations `let`.
  - Noms de paramètres sur les sites d'appel.
  - Indicateurs de déplacement linéaire (`move`) et de projection (`inout`).

---

## 4. Bibliothèque Standard Haute Performance v0.1.1

### 4.1. Moteur de Base de Données Embarqué Zéro-Copie (`std/db`)

Pour éliminer toute dépendance C externe (ex: SQLite) et garantir une sécurité mémoire totale, IFA v0.1.1 intègre un moteur de stockage embarqué natif en pur IFA :
- **Architecture de Stockage :**
  - Moteur hybride B+Tree / Log-Structured avec journal Write-Ahead Log (WAL) déterministe.
  - Format de bloc paginé à taille fixe (4096 octets), aligné sur les frontières de page OS.
  - Zéro allocation dynamique sur les lectures grâce au mapping mémoire direct (`mmap`) et aux slices typées IFA.
- **Garanties ACID & Concurrence :**
  - Transactions isolées (Snapshot Isolation) compatibles avec les fibres M:N.
  - Écritures atomiques avec fsync contrôlé et validation cryptographique d'intégrité par checksum BLAKE3 sur chaque en-tête de bloc.
- **Interface Publique :**
```ifa
pub struct Database {
    // Descripteur interne de base et verrous de transaction
}

pub struct Transaction {
    // Contexte de transaction isolé
}

impl Database {
    pub fn open(path: string) -> result<Database, DbError>;
    pub fn begin_tx(inout self) -> result<Transaction, DbError>;
    pub fn get(self, key: [u8]) -> result<option<[u8]>, DbError>;
    pub fn put(inout self, key: [u8], val: [u8]) -> result<(), DbError>;
    pub fn delete(inout self, key: [u8]) -> result<bool, DbError>;
    pub fn sync(inout self) -> result<(), DbError>;
}
```

### 4.2. Analyseur HTTP Vectorisé par SIMD (`std/net/simd_parser`)

L'analyseur HTTP standard est optimisé par l'utilisation d'instructions vectorielles (AVX2 sur x86_64, NEON sur AArch64, SIMD128 sur Wasm) :
- Recherche simultanée sur 16 ou 32 octets des délimiteurs de protocole (`\r\n`, `:`, espaces, tabulations).
- Décodage zéro-copie des en-têtes HTTP/1.1 à une vitesse dépassant 3,5 Go/s par cœur.
- Préparation de la machine à états pour le cadrage (framing) HTTP/2 et la compression HPACK.

```
Buffer d'entrée : [G][E][T][ ][/][a][p][i][/][v][1][ ][H][T][T][P][/][1][.][1][\r][\n] ...
Vecteur SIMD 32B: [ Recherche vectorisée de '\r' et ' ' en 1 cycle d'instruction ]
Indices trouvés : Méthode = "GET", Chemin = "/api/v1", Version = "HTTP/1.1"
```

---

## 5. Gestionnaire de Paquets Kori v0.1.1

### 5.1. Espaces de Travail Multi-Paquets (`kori workspace`)

Kori supporte désormais nativement la gestion des monorepos :
- Manifeste racine déclarant les membres :
```toml
[workspace]
members = [
    "core",
    "services/auth",
    "services/gateway",
    "shared/models",
]
```
- Résolution unifiée du graphe de dépendances avec déduplication stricte des versions et génération d'un unique fichier de verrouillage déterministe `kori.lock`.
- Ordonnancement topologique des builds et compilation parallèle sans interférences.

### 5.2. Sécurité Cryptographique & Signatures Ed25519

Pour garantir la chaîne de confiance logicielle :
- Chaque publication (`kori publish`) calcule l'empreinte BLAKE3 de l'archive tarball du paquet et appose une signature Ed25519 à l'aide de la clé privée de l'auteur.
- Le fichier `kori.lock` consigne pour chaque dépendance :
  - L'URL de téléchargement.
  - Le digest BLAKE3 (`integrity = "blake3-..."`).
  - La clé publique du signataire et la signature numérique.
- Lors de l'installation (`kori install` / `kori fetch`), toute non-concordance de signature ou de somme de contrôle déclenche un arrêt d'urgence immédiat.

---

## 6. Plan d'Implémentation et Jalons Techniques v0.1.1

| Domaine Technique | Composants Clés | Fichiers Cibles | Critères d'Acceptation |
|---|---|---|---|
| **Wasm Component Model** | Encodage Wasm 3.0, Canonical ABI, WIT Bindgen | `crates/ifa-wasm/src/wit/`, `crates/ifa-wasm/src/component.rs` | Compilation et validation d'un composant WASI 0.2 avec Wasmtime sans avertissement |
| **LSP 3.17 Avancé** | Index multi-fichiers, Rename global, Invariants Comptime | `crates/ifa-lsp/src/analysis_ext.rs`, `handlers/rename.rs` | Renommage d'un symbole partagé sur 5 fichiers avec zéro faux positif |
| **Stdlib Industrielle** | Base embarquée `std/db`, Parser SIMD HTTP | `crates/ifa-stdlib/src/db.rs`, `crates/ifa-stdlib/src/simd_parser.rs` | Benchmark de lecture > 100k ops/sec sur DB et 3 Go/s sur HTTP parser |
| **Kori Multi-Paquets** | Résolveur workspace, Signatures Ed25519 | `/root/kori/src/workspace.ifa`, `/root/kori/src/crypto.ifa` | Validation d'un workspace 3 paquets avec lockfile unifié déterministe |

---

## 7. Conformité & Préservation du Déterminisme

Toutes les évolutions prévues respectent strictement la charte d'ingénierie IFA :
1. **Zéro non-déterminisme :** Tri déterministe sur les symboles, les tables de types et les dictionnaires d'exports.
2. **Indépendance d'environnement :** Banni tout timestamp non contrôlé ou chemin absolu d'hôte dans les métadonnées émises.
3. **Point fixe préservé :** L'ajout des extensions dans le compilateur doit maintenir l'égalité stricte du triple bootstrap sur tous les backends natifs.
