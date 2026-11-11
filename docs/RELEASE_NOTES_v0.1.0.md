# IFA v0.1.0 — Notes de Version Officielles
**Date de publication** : 11 Novembre 2026  
**Auteur et Architecte** : ASSOGBA Prudence Dieudonné ([@jprud67](https://github.com/jprud67))  
**Licence** : Double licence MIT ou Apache-2.0  
**Dépôt officiel** : [github.com/ifa-lang/ifa](https://github.com/ifa-lang/ifa)

---

## 1. Vue d'Ensemble

Nous sommes fiers d'annoncer la première version publique officielle d'**IFA** (version **0.1.0**), un langage de programmation système moderne, déterministe et conçu pour garantir une **sécurité mémoire absolue** sans compromettre les performances d'exécution ni imposer de surcharge cognitive.

Inspiré des principes mathématiques et logiques du système Fa, IFA résout la tension historique entre sécurité et productivité :
- **Zéro Ramasse-Miettes (GC)** : Pas d'interruptions aléatoires de temps d'arrêt (Stop-The-World), empreinte mémoire prédictible et adaptée aux environnements temps réel et contraints.
- **Zéro Emprunt Manuel (Borrow Checker)** : Aucune annotation de durée de vie (*lifetimes*), suppression des frictions d'emprunt tout en conservant une sûreté mémoire démontrable.
- **Concurrence Incolore (Colorless Fibers)** : Fin de la dichotomie `sync`/`async` ; exécution concurrente massive sur threads M:N avec vol de travail équilibré.
- **Auto-Hébergement Intégral et Point Fixe Déterministe** : Le compilateur écrit en pur IFA est capable de se compiler lui-même de manière bit-à-bit déterministe.

---

## 2. Piliers et Innovations Architecturales

### 2.1 Sémantique de Valeur Mutable & Copy-on-Write (CoW)
Toutes les structures de données en IFA se comportent comme des valeurs isolées. La modification d'une variable garantit l'absence d'effets de bord imprévus sur d'autres références grâce à une stratégie d'analyse statique couplée à un mécanisme de Copy-on-Write transparent. L'aliasing mutable indésirable est rendu impossible au niveau sémantique.

### 2.2 Références Générationnelles
Pour modéliser des graphes, des arbres arbitraires ou des structures cycliques, IFA fournit des références générationnelles surveillées. Chaque accès est validé en temps constant ($O(1)$) contre la génération courante de l'arène allouée, éliminant totalement les déréférencements de pointeurs invalides (*use-after-free*, *dangling pointers*).

### 2.3 Concurrence Incolore et Ordonnanceur M:N
Grâce à un ordonnanceur de fibres légères (`GLOBAL_SCHEDULER`) sans famine de threads ouvriers, les opérations d'entrées/sorties et de temporisation sont suspendues de manière non-bloquante au niveau de la fibre sans monopoliser les cœurs de processeur.

### 2.4 Métaprogrammation `comptime`
Évaluation d'expressions et de fonctions au moment de la compilation pour le calcul de tables pré-optimisées, la génération de code typé et la vérification formelle d'invariants statiques.

---

## 3. Réalisations Majeures de la v0.1.0

### Axe A — Compilateur & Certification Tri-Plateforme
- **Point Fixe Déterministe Certifié** : Validation cryptographique du bootstrap triple étage :
  $$\text{SHA256}(\text{ifac-gen2}) = \text{SHA256}(\text{ifac-gen3})$$
- **Backend d'Émission Directe Multi-Cible** :
  - **Linux / BSD (ELF64)** : Tables de symboles complètes, sections `.text`, `.rodata`, `.data`, `.bss`, et métadonnées DWARF v5 déterministes.
  - **macOS (Mach-O 64)** : Prise en charge des architectures `x86_64` et `arm64`, en-têtes canoniques, tables `__compact_unwind` et sous-système dynamique `dysymtab`.
  - **Windows (PE32+/COFF)** : Prise en charge 64-bit native avec répertoires d'exceptions structurées `.pdata`/`.xdata`, base relocations pour l'ASLR dynamique, Import Directory Table (IAT), Delay-Load thunks, et Export Address Table (EAT) dans `.edata` pour la génération de bibliothèques DLL partageables.

### Axe B — Bibliothèque Standard Complète (`std/`)
La bibliothèque standard pure IFA comprend 10 modules fondamentaux, validés par **271 tests unitaires automatisés** (100 % de réussite) :
1. **`std/net`** : Primitives TCP/UDP, résolveur DNS, et serveur/client HTTP/1.1 concurrent non-bloquant.
2. **`std/crypto`** : Hachage rapide BLAKE3, SHA-256, cryptographie asymétrique Ed25519, et chiffrement authentifié ChaCha20-Poly1305.
3. **`std/io`** : Abstractions de flux d'entrée/sortie, tampons de lecture/écriture, et formateurs.
4. **`std/fs`** : Opérations de système de fichiers portables, métadonnées, parcours d'arborescences.
5. **`std/process`** : Gestion de sous-processus, transmission d'arguments, tubes d'E/S et signaux.
6. **`std/sync`** : Canaux typés multi-producteurs/multi-consommateurs, barrières et verrous non-bloquants.
7. **`std/time`** : Horloges monotones de haute précision, gestion de durées et timers pour fibres.
8. **`std/collections`** : Table de hachage déterministe (`HashMap`), tableaux redimensionnables (`Vec`), files (`Queue`) et ensembles (`Set`).
9. **`std/json`** : Parser et sérialiseur JSON sans allocation superflue.
10. **`std/csv`** : Lecteur et émetteur de flux tabulaires conformes à la norme RFC 4180.

### Axe C — Gestionnaire de Paquets `kori` en Pur IFA
- Émancipation complète dans `/root/kori` sous forme de modules IFA autonomes (`manifest.ifa`, `resolver.ifa`, `builder.ifa`, `cache.ifa`, `main.ifa`).
- Résolveur de dépendances déterministe respectant la sémantique de versionnement (SemVer 2.0.0).
- Fichier de verrouillage reproductible (`kori.lock`).
- Cache local adressable par le contenu avec vérification d'intégrité BLAKE3.

### Axe D — Applications de Démonstration Industrielle
Deux applications complètes ont été éprouvées dans le dépôt (`examples/`) :
- **`examples/http_service`** : Serveur REST de métriques et transactions avec requêtes concurrentes, sérialisation JSON, et gestion gracieuse de l'arrêt.
- **`examples/data_processor_cli`** : Utilitaire de traitement par lots de flux CSV/JSON avec agrégats statistiques, filtrage multi-critères et reporting instantané.

### Axe E — Outillage Développeur (DX) & Documentation
- **LSP 3.17 (`ifa-lsp`)** : Complétion de code, diagnostic syntaxique et sémantique en temps réel, navigation vers la définition.
- **Formateur Canonique (`ifa fmt`)** : Normalisation déterministe du style de code source.
- **Linter Statique (`ifa lint`)** : Détection des constructions inefficaces et conformité aux règles d'isolation mémoire.
- **Générateur de Documentation (`ifa doc`)** : Extraction automatique de la documentation en Markdown et HTML.
- **Guide Pratique d'Onboarding** : Rédaction de [TOUR_OF_IFA.md](TOUR_OF_IFA.md) offrant un parcours guidé en 15 minutes avec exemples immédiatement exécutables.

---

## 4. Démarrage Rapide

### 4.1 Installation depuis les Binaires Précompilés
Téléchargez l'archive correspondant à votre architecture depuis la section [Releases](https://github.com/ifa-lang/ifa/releases) :

```bash
# Exemple pour Linux x86_64
tar -xzf ifa-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
cd ifa-v0.1.0-x86_64-unknown-linux-gnu
export PATH="$(pwd)/bin:$PATH"

ifa --version
kori --version
```

### 4.2 Créer et Exécuter un Premier Projet
```bash
# Initialiser un nouveau projet
ifa new mon_service
cd mon_service

# Exécuter l'application
ifa run
```

---

## 5. Remerciements et Vision Future

Cette version **v0.1.0** pose les fondations stables et reproductibles de l'écosystème IFA. Nous remercions la communauté pour ses retours et contributions.

Les axes futurs de la prochaine série de versions porteront sur :
- L'enrichissement des backends matériels natifs supplémentaires (RISC-V 64).
- Le packaging automatisé pour les gestionnaires de paquets systèmes (Homebrew, APT, Pacman).
- L'intégration de solveurs SMT formels pour la vérification statique complète des invariants de sécurité mémoire.
