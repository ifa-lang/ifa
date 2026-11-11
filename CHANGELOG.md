# Journal des Modifications (Changelog)

Toutes les modifications notables apportées au projet **IFA** sont documentées dans ce fichier.
Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/), et ce projet adhère aux principes de [Semantic Versioning](https://semver.org/lang/fr/).

## [0.1.0] - 2026-11-11

### Ajouté
- **Compilateur Auto-Hébergé** : Point fixe déterministe certifié bit-à-bit via triple bootstrap (`sha256(ifac-gen2) == sha256(ifac-gen3)`).
- **Backend Tri-Plateforme Natif** : Émission binaire directe sans assembleur externe pour ELF64 (Linux), Mach-O 64 (macOS arm64/x86_64) et PE32+/COFF (Windows x64).
- **Support Débogage et Sécurité Système** :
  - Tables DWARF v5 complètes sous ELF64.
  - Tables de déroulement d'appels `__compact_unwind` et `dysymtab` sous Mach-O.
  - Gestion des exceptions `.pdata`/`.xdata`, tables de relocalisation de base pour ASLR dynamique, Import Directory Table (IAT), Delay-Load thunks et Export Address Table (EAT) sous PE32+/COFF.
- **Modèle Mémoire Déterministe** :
  - Sémantique de valeur mutable avec Copy-on-Write (CoW) transparent.
  - Références générationnelles sécurisées avec validation $O(1)$ contre les déréférencements obsolètes.
- **Système de Concurrence Incolore** :
  - Runtime de fibres légères M:N avec ordonnanceur à vol de travail non-bloquant.
  - Élimination de la famine de threads ouvriers dans `GLOBAL_SCHEDULER` pour les serveurs et clients réseau concurrents.
- **Bibliothèque Standard Complète (`std/`)** :
  - 10 modules standards fondamentaux : `std/net`, `std/crypto`, `std/io`, `std/fs`, `std/process`, `std/sync`, `std/time`, `std/collections`, `std/json`, `std/csv`.
  - 271 tests unitaires automatisés validés à 100 %.
- **Gestionnaire de Paquets Kori en Pur IFA** :
  - Modules autonomes dans `/root/kori` (`manifest.ifa`, `resolver.ifa`, `builder.ifa`, `cache.ifa`, `main.ifa`).
  - Résolution déterministe SemVer 2.0.0, génération de `kori.lock` et cache BLAKE3.
- **Applications Industrielles de Démonstration (Dogfooding)** :
  - Microservice HTTP concurrent avec routage REST et encodage JSON (`examples/http_service`).
  - Utilitaire de ligne de commande de traitement et d'agrégation de données CSV/JSON (`examples/data_processor_cli`).
- **Outillage et DX (Developer Experience)** :
  - Serveur de langage LSP 3.17 (`ifa-lsp`) avec autocomplétion et diagnostics temps réel.
  - Formateur canonique (`ifa fmt`) et linter d'analyse statique (`ifa lint`).
  - Générateur de documentation technique Markdown et HTML (`ifa doc`).
  - Guide d'accueil et d'embarquement rapide (`docs/TOUR_OF_IFA.md`).
- **Distribution et Packaging Multi-Plateformes** :
  - Script d'empaquetage automatisé `scripts/package_release.sh` avec génération d'archives tarball et calcul d'empreintes SHA256 (`SHA256SUMS`).
  - Workflow de publication continue GitHub Actions pour les releases officielles.
