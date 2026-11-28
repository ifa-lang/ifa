# Architecture et Spécification Technique : Canaux Typés Génériques en IFA Natif (`Channel<T>`)

## 1. Contexte et Problématique

Le langage système IFA propose une concurrence par fibres légères $M:N$ « incolores » (colorless concurrency), éliminant la dichotomie synchrone/asynchrone ainsi que la contagion des mots-clés `async`/`await`. Les fibres partagent un pool d'exécution sans ramasse-miettes (GC-free), orchestré par un planificateur coopératif à vol de travail (work-stealing) sur architectures multi-cœurs.

Actuellement, l'infrastructure de synchronisation inter-fibres se compose de deux niveaux :
1. **Runtime bas niveau (`ifa-runtime` & `ifa-fir`) :**
   - Implémentation en Rust de `Channel<T>` (`crates/ifa-runtime/src/fiber.rs`) reposant sur des tampons annulaires atomiques sans verrou (`AtomicRingBuffer<T>`) pour les canaux bornés, et des files chaînées protégées pour les canaux non bornés.
   - Instructions FIR dédiées : `ChanCreate`, `ChanSend`, `ChanTrySend`, `ChanRecv`, `ChanTryRecv`, `ChanClose`, et `ChanSelect`.
   - Prise en charge FFI C/ABI via `ifa_rt_channel_create`, `ifa_rt_channel_send`, `ifa_rt_channel_recv`.
2. **Bibliothèque standard native pure IFA (`std/sync.ifa`) :**
   - Structure `Channel` monomorphe encapsulant un identifiant 64-bit (`id: i64`), une capacité (`capacity: i64`) et un drapeau de fermeture (`is_closed: bool`).
   - Fonctions de transfert spécialisées par type : `channel_send_msg` / `channel_recv_msg` pour `i64`, et `channel_send_text` / `channel_recv_text` pour `String`.

### Limites constatées
- **Absence de typage statique générique en surface IFA :** Les exemples utilisateurs et le code applicatif (`examples/channel_benchmark.ifa`, `examples/colorless_fibers.ifa`) expriment déjà naturellement des types tels que `sync::Channel<i64>` ou `sync::Channel<Order>`.
- **Manque de polymorphisme unifié :** L'absence d'une abstraction `Channel<T>` oblige l'utilisateur à distinguer manuellement les fonctions d'envoi selon le type (`send_msg` vs `send_text`), ce qui empêche le transfert direct de structures définies par l'utilisateur sans passer par une sérialisation intermédiaire.
- **Vérification d'échappement :** Le compilateur (`ifa-sema`) dispose de la règle `E0072` (interdisant le transit de références locales `ref` dans les canaux inter-fibres), mais celle-ci doit être étendue de façon transparente aux types génériques instanciés.

---

## 2. Modèle Conceptuel et Architecture Cible

### 2.1. Structure du Type `Channel<T>`
En IFA natif, le type `Channel<T>` est une structure générique à sémantique de ressource gérée :

```ifa
pub struct Channel<T> {
    id: i64,
    capacity: i64,
    is_closed: bool
}
```

Le paramètre de type `T` est un paramètre générique fantôme au niveau de la structure d'état (phantom type parameter), garantissant le respect statique des types lors des opérations d'envoi (`send`), de réception (`recv`) et de multiplexage (`select`), tout en conservant une représentation mémoire compacte et uniforme de 24 octets (3 mots machine de 64 bits).

### 2.2. Taxonomie des Payloads Supportés

| Catégorie de Type | Types Concrets | Mode de Transfert Mémoire | Garantie de Sécurité |
| :--- | :--- | :--- | :--- |
| **Scalaires Primitifs** | `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, `u32`, `u64`, `bool`, `f32`, `f64` | Copie directe par valeur (registre ou slot 64-bit) | Zéro allocation, bitwise copy, safe |
| **Chaînes de Caractères** | `String` | Pointeur de payload + longueur (sémantique move) | Pas de double-free, transfert de possession |
| **Structures Utilisateur** | `struct Foo { ... }` | Copie bit-à-bit pour structures valeur ou pointeur heap | Respect de la disposition mémoire C-ABI |
| **Collections et Slices** | `List<T>`, `Slice<T>` | Descripteur de slice `{ ptr, len, cap }` | Move ownership, non partagé |
| **Références Locales** | `ref T`, `&T` | **INTERDIT** (rejet statique à la compilation) | Prévention stricte des *dangling pointers* inter-fibres |

---

## 3. Analyse Sémantique et Échappement (Zéro-GC Safety)

L'un des invariants fondamentaux d'IFA est l'absence de ramasse-miettes. Par conséquent, la transmission de données entre fibres légères (qui peuvent s'exécuter de manière concurrente sur des cœurs CPU distincts) doit obéir à des règles de transfert strictes :

1. **Règle d'Exclusion des Références Locales (`type_contains_ref`) :**
   Tout canal `Channel<T>` où $T$ contient directement ou récursivement une référence de pile `ref U` est formellement rejeté avec le code diagnostic `E0072` :
   $$\forall T, \quad \text{contains\_ref}(T) \implies \text{TypeError}(\text{E0072})$$
2. **Sémantique de Déplacement (Move Semantics) :**
   Lors de l'appel à `ch.send(val)`, la valeur `val` est déplacée dans le tampon du canal. L'analyseur sémantique invalide la variable locale d'origine si celle-ci possède des ressources dynamiques (tampon heap, handle d'E/S).
3. **Monomorphisation et Spécialisation des Fonctions Associées :**
   Pour chaque type concret $T$ utilisé dans un programme, le compilateur synthétise les spécialisations des fonctions de canal associées :
   - `Channel__send__<T>(inout ch: Channel<T>, val: T) -> bool`
   - `Channel__recv__<T>(inout ch: Channel<T>) -> T`
   - `Channel__try_send__<T>(inout ch: Channel<T>, val: T) -> bool`
   - `Channel__try_recv__<T>(inout ch: Channel<T>) -> ?T`

---

## 4. Ordonnancement Coopératif et Mécanique de Backpressure

Le canal coopératif IFA opère sans bloquer les threads du système d'exploitation sous-jacent :

```
                +------------------------------------+
                | Fibre Productrice (ch.send(val))   |
                +------------------------------------+
                                  |
                                  v
                  [ Canal Biaisé / Bounded ? ]
                     /                    \
                   OUI                    NON (Unbounded)
                   /                        \
      [ Tampon plein ? ]                     v
       /             \             [ Insertion dans file ]
     NON             OUI                     |
      |               |                      v
      v               v             +--------------------+
[ Push Atomique ]  [ Backoff Adaptatif ]   | Notification Waiters|
      |               |             +--------------------+
      v               +-----> [ fiber_yield() ]
[ Notification ]                     |
                                     v
                        [ Réveil sur slot libre ]
```

### 4.1. Algorithme de Backpressure à 3 Paliers
Lors de l'écriture sur un canal plein (`try_send` retourne `false`) :
1. **Palier 1 (Spins courts, < 32 itérations) :** Appel de `std::hint::spin_loop()` pour absorber les micro-latences sans changement de contexte.
2. **Palier 2 (Contention intermédiaire, 32 à 64 itérations) :** Appel coopératif à `fiber_yield()` / `yield_now()`, replaçant la fibre courante en queue du planificateur local.
3. **Palier 3 (Contention prolongée, > 64 itérations) :** Mise en sommeil de la fibre sur variable de condition associée au canal (`condvar`), réveillée par le consommateur lors de l'extraction d'un élément.

---

## 5. Interface de Programmation Native (`std/sync`)

L'API exposée dans la bibliothèque standard pure IFA `std/sync.ifa` doit être enrichie pour supporter harmonieusement les styles idiomatiques :

### 5.1. Constructeurs de Canaux
```ifa
// Canal non borné (asynchrone avec croissance dynamique)
pub fn channel<T>() -> Channel<T> {
    let cid = channel_create(0);
    return Channel(id: cid, capacity: 0, is_closed: false);
}

// Canal borné haute performance (adossé à l'AtomicRingBuffer lock-free)
pub fn bounded<T>(capacity: i64) -> Channel<T> {
    let cid = channel_create(capacity);
    return Channel(id: cid, capacity: capacity, is_closed: false);
}

// Alias historique de compatibilité
pub fn make_channel(capacity: i64) -> Channel {
    return bounded(capacity);
}
```

### 5.2. Opérations de Transfert
```ifa
// Envoi avec attente coopérative sur contre-pression
pub fn channel_send<T>(inout chan: Channel<T>, val: T) -> bool;

// Envoi non-bloquant immédiat
pub fn channel_try_send<T>(inout chan: Channel<T>, val: T) -> bool;

// Réception avec attente coopérative
pub fn channel_recv<T>(inout chan: Channel<T>) -> T;

// Réception non-bloquante immédiate (retourne optionnel ?T)
pub fn channel_try_recv<T>(inout chan: Channel<T>) -> ?T;

// Clôture du point de terminaison
pub fn channel_close<T>(inout chan: Channel<T>);
```

### 5.3. Contrôle Coopératif
```ifa
// Cède immédiatement la tranche d'exécution de la fibre courante
pub fn yield_now() {
    fiber_yield();
}
```

---

## 6. Intégration avec la Sémantique `select`

La construction syntaxique native `select` d'IFA est le mécanisme privilégié de multiplexage inter-canaux :

```ifa
select {
    let order = orders_chan => {
        process_order(order);
    },
    let signal = cancel_chan => {
        terminate_worker();
    },
    default => {
        sync::yield_now();
    }
}
```

Pour chaque branche `let var = chan => { ... }` :
1. L'analyseur sémantique (`ifa-sema`) déduit le type de `var` directement à partir du paramètre générique $T$ de `Channel<T>`.
2. Le lowering FIR (`ifa-fir`) génère un test non-bloquant `ChanTryRecv` sur le canal correspondant.
3. Si plusieurs canaux sont prêts simultanément, une politique d'arbitrage équitable ou prioritaire est appliquée sans famine.

---

## 7. Plan de Transition et Continuité

1. **Cycle #746 (Ce cycle) :** Spécification formelle de l'architecture générique `Channel<T>`, définition des invariants de mémoire et de sécurité d'échappement, ajout de l'utilitaire coopératif `yield_now()` dans `std/sync.ifa`.
2. **Cycle #747 :** Extension de `std/sync.ifa` pour introduire les constructeurs génériques `channel<T>()` et `bounded<T>(capacity)`, ainsi que les fonctions de transfert polymorphes typées, avec tests unitaires automatisés validant les primitives.
3. **Cycle #748 :** Optimisation de l'ordonnanceur de fibres face aux contentions concurrentes intenses (mécanisme de backoff adaptatif multi-paliers et intégration métrique dans l'audit de ressources).
