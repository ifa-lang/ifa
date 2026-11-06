# Exemple de Projet Kori & Pont FFI Symfony 8.1 / PHP 8.4+

Ce projet démontre l'utilisation de l'outillage unifié `kori` et de l'intégration native C-ABI :

### Compilation avec Kori
```bash
# Compilation en mode dev (Cranelift)
kori build

# Compilation en mode release optimisé (LLVM)
kori build --release

# Exécution de l'exécutable
kori run
```

### Artefacts Générés
- `target/dev/fintech_cli` : Exécutable binaire natif
- `target/dev/libfintech_core.so` : Bibliothèque dynamique C-ABI partagée
- `target/dev/fintech_core.h` : En-tête C-ABI généré automatiquement
- `target/dev/FintechNativeBridge.php` : Service d'intégration PHP 8.4+ / Symfony 8.1 FFI
