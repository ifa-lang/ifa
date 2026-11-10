# IFA High-Performance HTTP REST Microservice

Ce projet démontre l'implémentation d'un microservice API REST en syntaxe pure IFA exploitant les sous-systèmes de la bibliothèque standard `std/net` et `std/json`.

## Fonctionnalités

- **Transport réseau non-bloquant** : Utilisation des primitives de flux TCP et serveur HTTP `std/net`.
- **Routage REST déterministe** :
  - `GET /health` : Vérification de l'état du service et de l'horodatage système.
  - `GET /api/v1/orders` : Consultation de la liste des commandes réelles.
  - `POST /api/v1/orders` : Création transactionnelle d'une commande via payload JSON.
  - `PUT /api/v1/orders/:id` : Mise à jour du statut d'une commande existante.
  - `DELETE /api/v1/orders/:id` : Clôture/suppression d'une commande.
- **Sérialisation/Désérialisation JSON** : Encodage et décodage structurés sans allocation superflue.
- **Zéro dépendance externe** : Compilé et packagé nativement avec `kori`.

## Compilation et Tests

```bash
# Exécution de la suite de tests du service
kori test

# Compilation binaire native
kori build --release
```
