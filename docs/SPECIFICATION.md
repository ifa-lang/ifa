# **Spécification Technique & Architecture — Langage de Programmation IFA**

**Auteur & Architecte Principal :** ASSOGBA Prudence Dieudonné (@jprud67)  
**Date :** 6 novembre 2026  
Statut : Draft Architectural v0.1.0  
Extension des fichiers : .ifa  
Gestionnaire de paquets & Build System : kori (fichier de manifeste : kori.toml)  
Compilateur CLI : ifa

# **1\. Vision et Philosophie du Projet**

## **1.1. Origine et Symbolique**

IFA tire son nom du système divinatoire géomantique ouest-africain fondé sur une algèbre binaire stricte (traits simples et doubles) permettant de modéliser des états complexes et d'établir un diagnostic logique infaillible. Appliqué à l'ingénierie des systèmes, IFA incarne un compilateur déterministe qui vérifie mathématiquement la sûreté du programme sans imposer la lourdeur cognitive des systèmes de types empruntés traditionnels.

## **1.2. Le Problème Résolu (Au-delà du Triangle de Fer)**

En programmation système moderne, les langages actuels imposent un compromis :

* **Go / Java / C\# :** Simplicité et sécurité via un Garbage Collector (GC), au prix de latences imprévisibles et d'une empreinte mémoire élevée.  
* **C / C++ / Zig :** Performances maximales et contrôle bas niveau, mais exposition aux failles critiques de sécurité mémoire (*Use-After-Free*, *Double Free*, *Data Races*) ou gestion manuelle exigeante.  
* **Rust :** Sécurité mémoire sans GC et performances natives, mais au prix d'une charge cognitive élevée liée au *Borrow Checker*, d'une incapacité chronique à modéliser simplement des structures auto-référentielles (graphes, arbres DOM/UI, listes doublement chaînées), d'une fragmentation de l'écosystème asynchrone ("coloration" des fonctions `async`/`sync`) et de temps de compilation longs.

**L'objectif de IFA :** Briser ce compromis en combinant la **sûreté mémoire absolue sans Garbage Collector**, la **performance bare-metal**, et une **ergonomie de développement fluide** proche de TypeScript ou PHP 8.4+.

# **2\. Les 4 Piliers Architecturaux de IFA**

## **2.1. Modèle Mémoire Hybride : Sémantique de Valeur Mutable \+ Références Générationnelles**

Pour rendre le Borrow Checker et les annotations de durées de vie ('a) obsolètes, IFA repose sur deux mécanismes complémentaires :

1. **Sémantique de Valeur Mutable (inspirée de Hylo) :** Par défaut, chaque variable possède une source unique de vérité. Les passages d'arguments et mutations sont optimisés silencieusement par le compilateur via le passage par projection (*in-place mutation*) et le *Copy-on-Write* (CoW) implicite. Aucune référence partagée implicite ne peut créer de *data race*.  
2. **Références Générationnelles (inspirées de Vale) pour les Graphes :** Lorsqu'une structure nécessite un partage d'état ou des références circulaires (ex. : arbre de fenêtrage d'un Web OS, graphe de transactions fintech, cache en mémoire), IFA utilise des allocations avec compteur de génération 64 bits. Chaque pointeur stocke la génération attendue de la cible. Le compilateur élimine statiquement 90 % des vérifications par analyse de portée, et les vérifications résiduelles à l'exécution coûtent une simple comparaison d'entier en 1 cycle CPU.

## **2.2. Possession (Ownership) Progressive (inspirée de Mojo)**

IFA s'adapte au cycle de vie du développement logiciel :

* **Mode Standard (Ergonomique) :** Inférence complète, gestion automatique de la mémoire par analyse statique et optimisations CoW. Idéal pour écrire rapidement de la logique métier, des contrôleurs d'API ou des scripts système.  
* **Mode Strict (`strict` / `owned`) :** Activé au niveau d'un module ou d'une fonction critique (moteur cryptographique, passerelle de paiement haute fréquence, noyau OS). Interdit toute allocation implicite sur le tas (*heap*), garantit le déterminisme temporel temps-réel et force l'allocation sur la pile (*stack*) ou dans des arènes mémoire pré-allouées (`Arena`).

## **2.3. Concurrence "Incolore" (Colorless Concurrency)**

IFA élimine la distinction syntaxique entre code synchrone et asynchrone :

* Aucune obligation de polluer les signatures avec `async` et `await`.  
* Toutes les opérations d'entrées/sorties (réseau, fichiers, sockets, timers) sont non-bloquantes par défaut et pilotées par un ordonnanceur léger à fibres (*green threads* en mode *work-stealing* basé sur `io_uring` sous Linux, `IOCP` sous Windows et les promesses hôtes sous WebAssembly).  
* Le compilateur génère automatiquement les machines à états de suspension lors de la compilation.

## **2.4. Métaprogrammation Unifiée par `comptime` (inspirée de Zig)**

* Suppression des langages de macros procédurales complexes et lents à compiler.  
* Utilisation du mot-clé `comptime` permettant d'exécuter du code IFA standard durant la phase de compilation pour générer des types génériques, valider des schémas JSON/SQL, ou précalculer des tables de routage HTTP avec un coût zéro à l'exécution.

# **3\. Tableau Comparatif : IFA vs Écosystème Actuel**

| Critère | Rust | Go | Zig | TypeScript / Node.js | IFA |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **Gestion Mémoire** | Borrow Checker \+ Lifetimes (`'a`) | Garbage Collector (GC) | Manuelle (Allocators explicites) | Garbage Collector (V8) | **Valeur Mutable \+ Réf. Générationnelles** |
| **Structures de Graphes / Arbres** | Très difficile (`Rc<RefCell<T>>` / `unsafe`) | Facile (GC) | Facile mais non sécurisé | Facile (GC) | **Natif, direct et 100 % sûr (`ref`)** |
| **Modèle Asynchrone** | Coloré (`async`/`await` \+ Tokio tiers) | Incolore (Goroutines) | Explicite / Bas niveau | Coloré (`async`/`await` mono-thread) | **Incolore natif (Fibres sans GC)** |
| **Métaprogrammation** | Macros déclaratives & procédurales lourdes | Génération externe (`go generate`) | `comptime` natif | Types conditionnels limités | **`comptime` natif en syntaxe IFA** |
| **Vitesse de Compilation** | Lente | Très rapide | Rapide | Rapide (Transpilation) | **Rapide (Backend Cranelift en dev, LLVM en prod)** |
| **Cibles Natives & WebAssembly** | Excellentes | Binaire Wasm lourd (GC inclus) | Excellentes | Non natif | **Binaire ultra-léger Natif & Wasm** |

# **4\. Spécification de la Syntaxe (Aperçu du Langage)**

## **4.1. Variables, Mutabilité et Sémantique de Valeur**

```
// Constante immuable par défaut (inférence de type)
let version = "0.1.0"

// Variable mutable (sémantique de valeur isolée)
mut compteur: u64 = 0
compteur += 1
```

## **4.2. Structures et Graphes Auto-Référentiels (Sans Borrow Checker)**

En Rust, créer un nœud d'interface graphique pointant vers son parent et ses enfants nécessite des contorsions complexes. En IFA, le mot-clé `ref` active une référence générationnelle sûre :

```
struct WindowNode {
    id: String,
    title: String,
    parent: ?ref WindowNode,
    children: List<WindowNode>
}

fn attach_child(inout parent: WindowNode, mut child: WindowNode) {
    child.parent = ref parent
    parent.children.push(child)
}
```

## **4.3. Serveur HTTP et Concurrence Incolore**

```
import net::http
import std::io
import encoding::json

struct PaymentPayload {
    merchant_id: String,
    amount_xof: u64,
    currency: String
}

fn main() {
    let port: u16 = 8080
    mut server = http::Server(port: port)

    server.post("/api/v1/charge", fn(req, res) {
        // Désérialisation validée à la compilation via comptime
        let payload = json::decode<PaymentPayload>(req.body()) catch err {
            return res.status(400).json({ error: "Payload invalide : {err.message}" })
        }

        // Appel I/O non-bloquant implicite (aucun mot-clé await requis)
        io::println("Traitement transaction pour {payload.merchant_id} : {payload.amount_xof} {payload.currency}")

        res.status(200).json({
            status: "success",
            tx_ref: "FA-TX-99482"
        })
    })

    io::println("Serveur Fa actif sur le port {port}")
    server.listen()
}
```

## **4.4. Mode Haute Performance (`strict`) et Métaprogrammation (`comptime`)**

```
// Fonction garantie sans aucune allocation sur le tas (zéro heap)
strict fn compute_hmac_sha256(payload: Slice<u8>, secret: Slice<u8>) -> [u8; 32] {
    // Exécution déterministe sur la pile
}

// Exécution à la compilation pour générer une table de hachage statique
comptime fn generate_crc_table() -> [u32; 256] {
    mut table = [0u32; 256]
    return table
}
```

# **5\. Architecture du Compilateur (`ifac`) et de l'Outillage (`kori`)**

Pour garantir une vélocité maximale dès la phase d'amorçage (*bootstrapping*), la première version du compilateur IFA est écrite en Rust, avant de devenir auto-hébergée (self-hosted en IFA à partir de la v1.0).

## **Pipeline de Compilation en 5 Phases**

1. **Lexer (`ifa-lexer`) :** Découpage du code source `.ifa` en flux de *Tokens* ultra-rapide (zéro copie via *string interning*).  
2. **Parser (`ifa-parser`) :** Analyseur descendant récursif (Pratt Parser pour les expressions) produisant l'Arbre de Syntaxe Abstraite (AST).  
3. **Analyse Sémantique & Typage (`ifa-sema`) :**  
   * Inférence de types Hindley-Milner locale.  
   * Résolution des appels `comptime` via une machine virtuelle bytecode intégrée.  
   * Analyse d'échappement (*Escape Analysis*) : détermine automatiquement si une donnée reste sur la pile (*Stack*), nécessite du *Copy-on-Write*, ou requiert un compteur générationnel.  
4. **Représentation Intermédiaire (`FIR` \- IFA Intermediate Representation) :** Graphe de flot de contrôle (SSA) optimisant les projections de valeurs et insérant automatiquement les points de suspension des fibres I/O.  
5. **Backends de Génération de Code :**  
   * **Profil Développement (`ifa run` / `ifa build --dev`) :** Backend **Cranelift** pour une compilation quasi-instantanée (inférieure à 0.5 seconde).  
   * **Profil Production (`ifa build --release`) :** Backend **LLVM** pour une optimisation agressive (vectorisation SIMD, inlining, LTO) vers x86\_64, ARM64 et **WebAssembly (WASM32/WASI)**.

## **Outillage Intégré Unifié (`kori`)**

* `ifa new <projet>` : Initialise l'arborescence avec `kori.toml` et `src/main.ifa`.  
* `ifa run` : Compile et exécute instantanément.  
* `ifa test` : Exécuteur de tests unitaires et benchmarks natif.  
* `ifa fmt` & `ifa lint` : Formateur canonique et analyseur statique intégrés.  
* `ifa lsp` : Serveur de langage (Language Server Protocol) natif pour l'autocomplétion temps réel dans VS Code, Cursor et environnements terminaux.  
* `kori add <package>` : Gestionnaire de dépendances déterministe avec verrouillage cryptographique (`kori.lock`).

# **6\. Cas d'Usage Cibles et Intégration Écosystème**

1. **Modules WebAssembly Haute Performance (Systèmes & Web OS) :** Compilation de moteurs de rendu, systèmes de fichiers virtuels et utilitaires système en binaires `.wasm` de quelques kilo-octets (sans runtime GC) pour propulser des environnements web modernes tels que des Web OS ou des applications **React / TypeScript**.  
2. **Passerelles Fintech & Microservices Critique :** Création de proxys API, moteurs de réconciliation financière et passerelles de paiement (Mobile Money, agrégateurs bancaires, conversion de devises) capables de traiter des dizaines de milliers de requêtes par seconde avec une latence constante (aucun *Stop-The-World* de Garbage Collector).  
3. **Extensions Natives pour Backends Existants (FFI C-ABI) :** Exportation transparente de fonctions IFA selon l'ABI C standard (`extern "C"`), permettant d'appeler des librairies IFA ultra-rapides directement depuis **PHP 8.4+ (via FFI)** ou **Node.js (via N-API)**.

# **7\. Feuille de Route (Roadmap d'Implémentation)**

* **Phase 1 — Fondations & Prototype (Mois 1 à 2\) :**  
  * Gel de la grammaire formelle EBNF du langage IFA.  
  * Implémentation du Lexer et du Parser en Rust (`ifa-lexer`, `ifa-parser`).  
  * Génération de l'AST et suite de tests syntaxiques.  
* **Phase 2 — Sémantique de Valeur & Premier Backend (Mois 3 à 4\) :**  
  * Vérificateur de types (`ifa-sema`) et implémentation des mutations sur place (`inout`).  
  * Intégration du backend Cranelift/LLVM pour compiler les premiers binaires exécutables (`Hello World`, arithmétique, structures, fonctions).  
* **Phase 3 — Références Générationnelles & `comptime` (Mois 5 à 6\) :**  
  * Implémentation de l'allocateur générationnel et du mot-clé `ref`.  
  * Moteur d'évaluation à la compilation (`comptime`).  
* **Phase 4 — Runtime I/O Incolore & Standard Library (Mois 7 à 9\) :**  
  * Ordonnanceur de fibres asynchrones transparentes (`net::http`, `std::fs`, `encoding::json`).  
  * Support cible WebAssembly (`wasm32-wasi`) et interopérabilité FFI C/PHP/Node.js.  
* **Phase 5 — Outillage `kori` & Open-Source (Mois 10 à 12\) :**  
  * Publication du gestionnaire de paquets `kori`, du serveur LSP (`ifa-lsp`) et lancement officiel du dépôt open-source.

# **8\. Spécification Approfondie de la Sémantique de Passage et Gestion d'Erreurs**

## **8.1. Les 4 Modes de Passage de Paramètres (Remplacement du Borrow Checker)**

Pour éliminer les annotations de durées de vie tout en conservant une performance native, le vérificateur sémantique applique quatre conventions d'appel sur les paramètres de fonctions :

* **Mode in (Implicite par défaut) :** Projection en lecture seule. Pour les types scalaires (entiers, flottants, booléens), la valeur est copiée dans un registre CPU. Pour les structures volumineuses, le compilateur passe automatiquement une adresse mémoire constante sans effectuer de copie. L'appelé ne peut ni muter ni conserver la référence après le retour de la fonction.  
* **Mode inout (Mutation exclusive sur place) :** Indique que la fonction modifie directement la variable fournie par l'appelant. Le compilateur vérifie statiquement la loi d'exclusivité : une même variable racine ne peut jamais être passée deux fois en inout (ou en inout et in simultanément) dans le même appel de fonction.  
* **Mode sink (Transfert de propriété / Move) :** La fonction prend possession de la valeur passée. La variable d'origine dans la fonction appelante devient inaccessible après l'appel, garantissant l'unicité du propriétaire sans compteur de référence.  
* **Mode comptime (Évaluation statique) :** Le paramètre doit être connu lors de la compilation. Permet la spécialisation générique et la génération de code typé sans coût à l'exécution.

## **8.2. Modèle d'Erreur par Valeur Déterministe (\! et catch)**

IFA n'utilise pas d'exceptions par déroulement de pile (stack unwinding) afin de préserver la prévisibilité des performances et un binaire WebAssembly minimal :

* Une fonction pouvant échouer déclare une signature de retour combinée sous la forme TypeErreur\!TypeSucces (exemple : IoError\!String).  
* Le mot-clé fail retourne immédiatement l'erreur à l'appelant via un registre dédié (drapeau de statut dans le registre secondaire de retour).  
* Le mot-clé try propage automatiquement l'erreur si la fonction englobante possède un type d'erreur compatible.  
* Le bloc catch err permet d'intercepter et de traiter localement l'erreur ou de fournir une valeur de repli.

# **9\. Spécification Bas Niveau du Modèle Mémoire et ABI Interne**

## **9.1. Architecture Binaire des Allocations Générationnelles**

Lorsqu'une structure est ciblée par une référence souple ref (pour construire des graphes, des arbres UI ou des caches), l'analyseur d'échappement alloue l'objet dans un allocateur par dalles (Slab Allocator) doté d'un en-tête de 64 bits nommé GenHeader :

| Champ de l'en-tête | Taille | Rôle technique |
| :---- | :---- | :---- |
| `generation_counter` | 32 bits (u32) | Compteur incrémenté atomiquement ou séquentiellement à chaque libération de l'objet propriétaire. |
| `allocation_flags` | 16 bits (u16) | Indique l'état du slot (Actif, Libéré, Épinglé en mémoire, Verrouillé en écriture). |
| `arena_id` | 16 bits (u16) | Identifiant de l'arène mémoire ou du thread propriétaire pour optimiser la localité du cache CPU. |

## **9.2. Représentation d'une Référence ref et Vérification en 1 Cycle CPU**

* Une référence ref est représentée en interne par un pointeur enrichi de 128 bits comprenant l'adresse mémoire directe du slot (ptr sur 64 bits) et la génération mémorisée lors de la création de la référence (remembered\_gen sur 32 bits).  
* Lors de l'accès à un champ via une référence ref, si le compilateur n'a pas pu prouver statiquement que la cible est toujours vivante, il émet une simple comparaison entière entre slot.generation\_counter et ref.remembered\_gen.  
* Si les deux valeurs diffèrent, le programme déclenche immédiatement une interruption sécurisée (Use-After-Free intercepté) avant toute corruption mémoire.

## **9.3. Algorithme d'Élimination Statique des Vérifications (Dominance Analysis)**

Pour atteindre 90 % à 100 % d'élimination des vérifications à l'exécution, la passe d'optimisation applique trois règles :

* **1\. Domination Lexicale Directe :** Si la création et l'utilisation de ref x se trouvent dans un bloc dominé par la déclaration de x, et que x ne subit aucun transfert sink, aucune vérification n'est générée.  
* **2\. Hissage hors des Boucles (Loop-Invariant Code Motion) :** Si une référence est lue de manière répétée dans une boucle sans appel susceptible de détruire son propriétaire, la vérification de génération est exécutée une seule fois avant d'entrer dans la boucle.  
* **3\. Isolation du Mode strict :** Dans une fonction annotée strict fn, seules les projections in et inout sur la pile ou sur des arènes pré-allouées sont autorisées, garantissant zéro vérification dynamique.

# **10\. Grammaire Formelle de Référence et Priorités d'Opérateurs**

## **10.1. Règles Syntaxiques Principales (Contrat pour le Parseur)**

* **Déclaration de module et d'import :** import chemin::vers::module (avec alias optionnel as alias).  
* **Déclaration de fonction :** \[pub\] \[strict \| comptime \| extern\] fn nom\_fonction(liste\_parametres) \-\> TypeRetour { corps }.  
* **Déclaration de structure :** \[pub\] struct NomStructure { champ1: Type1, champ2: Type2 }.  
* **Déclaration d'énumération (Type Somme / ADT) :** \[pub\] enum NomEnum { VarianteA, VarianteB(TypeAssocie) }.  
* **Instructions (Statements) :**  
  * `let ident: Type = expression` (liaison immuable par valeur).  
  * `mut ident: Type = expression` (liaison mutable).  
  * `defer { bloc }` (exécution garantie à la sortie de la portée courante, utilisée pour fermer des descripteurs systèmes ou libérer des ressources externes).  
  * `return expression` et `fail expression`.

## **10.2. Table de Précédence des Opérateurs (Du plus fort au plus faible)**

Pour l'implémentation de l'analyseur d'expressions (Pratt Parser), les niveaux de liaison (binding power) sont fixés ainsi :

* **Niveau 10 (Suffixes) :** Accès membre ., appel de fonction (), indexation \[\].  
* **Niveau 9 (Préfixes unaires) :** Négation \-, \!, création de référence ref, projection inout, transfert sink, propagation try.  
* **Niveau 8 (Multiplicatifs) :** \*, /, %.  
* **Niveau 7 (Additifs) :** \+, \-.  
* **Niveau 6 (Décalages binaires) :** Décalage gauche et droite.  
* **Niveau 5 (Comparaisons relationnelles) :** Égalité \==, différence \!=, infériorité et supériorité.  
* **Niveau 4 (Opérations binaires bit-à-bit) :** ET binaire, OU exclusif, OU inclusif.  
* **Niveau 3 (Conjonction logique) :** ET logique.  
* **Niveau 2 (Disjonction logique) :** OU logique.  
* **Niveau 1 (Interception et repli) :** Opérateur catch et coalescence d'option ??.

# **11\. Architecture Modulaire du Compilateur en Rust (Cargo Workspace)**

Pour accélérer le développement initial (bootstrapping), le compilateur ifac et le gestionnaire kori sont structurés en un Cargo Workspace Rust découpé en 12 crates indépendantes :

| Nom de la Crate | Responsabilité technique dans le pipeline | Dépendances Rust recommandées |
| :---- | :---- | :---- |
| `crates/ifa-span` | Gestion des fichiers sources, positions d'octets (Span) et internement de chaînes (Symbol) zéro-allocation. | lasso ou rodeo |
| `crates/ifa-diagnostics` | Formatage visuel des erreurs et avertissements dans le terminal avec pointeurs de lignes colorés. | ariadne ou codespan-reporting |
| `crates/ifa-lexer` | Découpage lexical rapide prenant en charge l'interpolation de chaînes et les littéraux numériques typés. | logos (ou automate manuel) |
| `crates/ifa-ast` | Définition des structures de l'Arbre de Syntaxe Abstraite (AST) et des traits de parcours (Visitor Pattern). | Standard uniquement |
| `crates/ifa-parser` | Parseur descendant récursif avec récupération sur erreur (Error Recovery) pour ne pas stopper au premier bug. | Standard \+ insta (tests snapshots) |
| `crates/ifa-sema` | Table des symboles, inférence de types bidirectionnelle, vérification de l'exclusivité inout et analyse d'échappement. | ena (unification Hindley-Milner) |
| `crates/ifa-comptime` | Machine virtuelle bytecode légère exécutant les fonctions comptime pendant la compilation. | Standard uniquement |
| `crates/ifa-fir` | Représentation Intermédiaire SSA spécifique à IFA (insertion automatique du Copy-on-Write et des instructions générationnelles). | petgraph (graphe de flot de contrôle) |
| `crates/ifa-codegen-cranelift` | Génération rapide de code natif et JIT pour le mode développement (ifa run). | cranelift-codegen, cranelift-module |
| `crates/ifa-codegen-llvm` | Génération de code hautement optimisé (x86\_64, ARM64, WebAssembly) pour la production (ifa build \--release). | inkwell (liaisons LLVM) |
| `crates/ifa-runtime` | Bibliothèque d'exécution minimale (no\_std) contenant l'allocateur générationnel et l'ordonnanceur de fibres I/O. | rustix, io-uring (Linux), windows-sys |
| `crates/kori` | Gestionnaire de paquets, lecture de kori.toml, résolution de versions et orchestration du cache de build. | serde, toml, clap, blake3 |

# **12\. Spécification du Manifeste kori.toml et Pont FFI PHP 8.4+ / C-ABI**

## **12.1. Configuration Standard d'un Projet (kori.toml)**

Chaque projet IFA est piloté par un fichier kori.toml à sa racine qui unifie la compilation, les dépendances et les cibles d'exportation :

* **Section \[package\] :** Définit name, version, edition \= "2026", authors et license.  
* **Section \[target\] :** Permet de cibler simultanément un exécutable natif (bin), une bibliothèque partagée compatible C (cdylib générant un fichier .so sous Linux ou .dll sous Windows), et un module WebAssembly (wasm32-wasi).  
* **Section \[profiles.dev\] :** Active par défaut le backend cranelift pour une compilation en moins de 500 millisecondes avec vérifications générationnelles complètes.  
* **Section \[profiles.release\] :** Active le backend llvm avec optimisation maximale (opt\_level \= 3, lto \= "thin", strip\_symbols \= true).

## **12.2. Intégration Native dans une Architecture PHP 8.4+ / C-ABI**

Grâce à l'absence de Garbage Collector dans IFA, toute fonction annotée pub extern "C" strict fn produit un symbole binaire C-ABI pur, sans surcharge de runtime. Cela permet de déporter les traitements lourds d'une application tournant sous **PHP 8.4+** directement vers une bibliothèque compilée en IFA :

* **1\. Côté IFA :** La fonction reçoit des pointeurs constants ou des tranches d'octets, exécute le calcul intensif (hachage cryptographique, agrégation financière massive, validation de lot JSON/CSV, signature de transaction) sur la pile en mode strict, et retourne le résultat.  
* **2\. Côté PHP 8.4+ :** Un service dédié charge la bibliothèque .so en préchargement (opcache.preload) via FFI::cdef(), offrant des appels de fonctions natives en quelques nanosecondes depuis les contrôleurs ou les workers.

# **13\. Plan d'Exécution Développeur — Checklist Granulaire des 4 Premiers Sprints**

Pour lancer le développement immédiatement et valider chaque brique de manière incrémentale :

* **Sprint 1 (Semaines 1 à 3\) — Socle Lexical, AST et Parseur :**  
  * Créer le dépôt Cargo Workspace et implémenter ifa-span et ifa-diagnostics.  
  * Coder l'analyseur lexical ifa-lexer avec tests unitaires sur tous les mots-clés (fn, let, mut, in, inout, sink, ref, strict, comptime, try, catch, fail).  
  * Implémenter ifa-parser et valider la génération de l'AST sur 50 fichiers d'exemples .ifa.  
* **Sprint 2 (Semaines 4 à 6\) — Typage, Loi d'Exclusivité et Sémantique de Valeur :**  
  * Implémenter la résolution des noms et la table des symboles dans ifa-sema.  
  * Coder l'inférence de types locale et le vérificateur d'exclusivité des projections in et inout.  
  * Valider la détection statique des erreurs de mutation concurrente.  
* **Sprint 3 (Semaines 7 à 9\) — Représentation FIR et Premier Exécutable Cranelift :**  
  * Abaisser l'AST typé vers le graphe SSA ifa-fir.  
  * Connecter ifa-codegen-cranelift pour émettre un fichier objet natif et le lier en binaire exécutable via la commande ifa run.  
  * Compiler et exécuter avec succès les premiers programmes utilisant l'arithmétique, les structures, les boucles et les appels de fonctions.  
* **Sprint 4 (Semaines 10 à 12\) — Allocateur Générationnel, Mot-clé ref et Pont C-ABI :**  
  * Implémenter l'allocateur par dalles avec en-tête GenHeader de 64 bits dans ifa-runtime.  
  * Activer la génération des instructions gen\_alloc, gen\_ref et gen\_check ainsi que la passe d'élimination statique par dominance.  
  * Générer la première bibliothèque partagée .so / .dll via pub extern "C" strict fn et tester son appel depuis un script PHP 8.4+ C-ABI.

