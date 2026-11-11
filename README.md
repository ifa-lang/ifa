# **IFA Programming Language**

[License: MIT/Apache 2.0](#licence) | [Release Notes v0.1.0](docs/RELEASE_NOTES_v0.1.0.md) | [Changelog](CHANGELOG.md) | [Quickstart & Tour of IFA](docs/TOUR_OF_IFA.md)

---

# **Vision**

**IFA** est un langage de programmation système moderne, déterministe et conçu pour offrir une **sûreté mémoire absolue** sans compromis sur la productivité ou les performances.

Inspiré par l'algèbre binaire stricte du système Fa, IFA résout le dilemme classique du développement système :

* Aucun Garbage Collector (GC) : Pas de pauses imprévisibles, empreinte mémoire minimale et prédictibilité temps réel.  
* Aucune charge cognitive de Borrow Checker : Pas d'annotations complexes de lifetimes ni de combat contre le compilateur.

IFA parvient à cet équilibre en combinant un modèle d'analyse statique des flux de données avec une sémantique de valeur structurée, offrant des garanties d'isolation strictes à l'échelle du thread tout en conservant la simplicité d'écriture d'un langage de haut niveau.

---

# **Fonctionnalités Clés**

## **Sémantique de Valeur Mutable (Copy-on-Write)**

Toutes les structures de données dans IFA se comportent comme des valeurs isolées. La mutation est locale et déterministe grâce à un mécanisme implicite et hautement optimisé de Copy-on-Write (CoW). L'aliasing mutable est physiquement impossible, éliminant d'emblée toute une classe de bugs de concurrence et de corruption de mémoire.

## **Références Générationnelles**

La modélisation de structures complexes (telles que les graphes ou les réseaux de nœuds) s'effectue sans effort. IFA utilise des références générationnelles sécurisées qui détectent statiquement et dynamiquement l'accès aux objets obsolètes (dangling pointers), garantissant une sécurité mémoire intégrale sans recourir à un glaneur de mémoire.

## **Concurrence Incolore (Fibres Natives)**

Fini la fragmentation de l'écosystème entre fonctions synchrones et asynchrones (async/await). IFA intègre un runtime de fibres légères et incolores planifiées en mode M:N. Vous écrivez du code séquentiel et lisible qui s'exécute de manière non-bloquante et hautement concurrente sur l'ensemble des cœurs système.

## **Métaprogrammation via comptime**

Exécutez du code IFA arbitraire au moment de la compilation. Le système comptime permet la génération de code typé, la réflexion statique, la vérification de contraintes complexes et l'optimisation avancée avant l'étape d'émission d'instructions binaires.

---

# **Exemple de Code : Serveur HTTP**

Voici un exemple concret illustrant la syntaxe et la simplicité d'un serveur HTTP écrit en IFA :

```
import std/net/http;
import std/io;

fn handle_request(req: http.Request) -> http.Response {
    match req.path {
        "/" => http.Response.ok("Hello, World!"),
        "/health" => http.Response.ok("OK"),
        _ => http.Response.not_found("Page non trouvée"),
    }
}

pub fn main() -> Result<(), io.Error> {
    let server = http.Server.bind("127.0.0.1:8080")?;
    println("Serveur HTTP démarré sur http://127.0.0.1:8080");

    // Les fibres incolores traitent chaque connexion de manière concurrente
    for client in server.incoming() {
        spawn fn() {
            if let Ok(req) = client.read_request() {
                let res = handle_request(req);
                let _ = client.send_response(res);
            }
        };
    }

    return Ok(());
}
```

---

# **Démarrage Rapide**

## **Prérequis**

* Rust (toolchain stable récente)  
* Cargo  
* CMake et LLVM/Cranelift (selon le backend sélectionné)

## **Compilation à partir des sources**

Clonez le dépôt et compilez la suite d'outils IFA :

```bash
# Cloner le dépôt
git clone https://github.com/ifa-lang/ifa.git
cd ifa

# Compiler l'ensemble du workspace
cargo build --release

# Vérifier le compilateur CLI
./target/release/ifa --help
```

## **Exécuter ou compiler un programme**

```bash
# Vérifier la syntaxe et la sémantique d'un fichier source
./target/release/ifa check examples/hello.ifa

# Inspecter l'arbre syntaxique abstrait (AST)
./target/release/ifa parse examples/window_tree.ifa

# Évaluer des expressions et fonctions comptime
./target/release/ifa comptime examples/crc_table.ifa

# Émettre et inspecter le graphe de flot de contrôle FIR SSA
./target/release/ifa fir examples/window_tree.ifa

# Exécuter un programme via l'interpréteur SSA FIR
./target/release/ifa run examples/window_tree.ifa

# Exécuter nativement en mémoire via le JIT Cranelift
./target/release/ifa run --native examples/hello.ifa

# Compiler en exécutable natif autonome (AOT)
./target/release/ifa build examples/hello.ifa -o hello
./hello
```

---

## Architecture du Workspace

Le compilateur IFA est structuré en un workspace modulaire en Rust :

| Crate | Rôle architectural |
|---|---|
| `ifa-span` | Gestion des fichiers sources, positions d'octets (`Span`) et internement de chaînes (`Symbol`). |
| `ifa-diagnostics` | Moteur de rendu terminal des erreurs et avertissements avec surlignage couleur via Ariadne. |
| `ifa-lexer` | Analyseur lexical rapide fondé sur Logos pour tous les mots-clés et littéraux IFA. |
| `ifa-ast` | Définition des structures de l'Arbre de Syntaxe Abstraite (AST) et visiteurs. |
| `ifa-parser` | Parseur récursif descendant et parseur d'expressions Pratt. |
| `ifa-sema` | Table des symboles, inférence de types, loi d'exclusivité `inout` et analyse d'échappement. |
| `ifa-comptime` | Machine virtuelle bytecode pour l'évaluation statique à la compilation. |
| `ifa-fir` | Représentation intermédiaire SSA (FIR), passes d'optimisation CoW et références générationnelles. |
| `ifa-runtime` | Bibliothèque d'exécution standard et déterministe (allocateur générationnel, ordonnanceur de fibres M:N, conteneurs CoW, flux I/O, ABI C). |
| `ifa-codegen-cranelift` | Backend de génération de code machine natif AOT (`.o`, ELF) et JIT haute performance via Cranelift. |
| `ifa-codegen-llvm` | Backend AOT alternatif et pont d'optimisation vectorielle via LLVM. |
| `ifa-wasm` | Compilateur et runtime d'exécution WebAssembly (Wasm/WASI). |
| `ifa-lsp` | Serveur de langage compatible LSP 3.17 pour éditeurs et IDE (VS Code, Neovim, etc.). |
| `ifa-stdlib` | Implémentation Rust et ponts d'interopérabilité pour la bibliothèque standard pure IFA (`std/`). |
| `kori` | Gestionnaire de paquets déterministe, orchestrateur de compilation et résolveur SemVer. |
| `ifa-cli` | Binaire CLI unifié (`ifa`) proposant les commandes `check`, `lex`, `parse`, `comptime`, `fir`, `run`, `build`, `fmt`, `lint`, `test`, `doc` et `new`. |

---

## Licence

Le projet IFA est distribué sous double licence selon vos besoins :

* **Licence MIT** ([LICENSE-MIT](LICENSE-MIT))
* **Licence Apache 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

### Exception Runtime

Les bibliothèques liées aux exécutables produits par le compilateur IFA bénéficient d'une exception d'utilisation (*Runtime Library Exception*), vous permettant de distribuer vos binaires compilés sous la licence de votre choix sans contrainte de redistribution du code source.

