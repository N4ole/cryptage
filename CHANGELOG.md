# Journal des modifications

Toutes les modifications notables de ce projet sont documentées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/)
et le projet respecte le [versionnage sémantique](https://semver.org/lang/fr/).

## [Unreleased]

### Ajouté
- Mise en place du dépôt : licence MIT, CI (fmt, clippy, tests, audit, deny, couverture), Dependabot.
- Format de fichier v1 : en-tête versionné de 60 octets (marqueur, version, paramètres Argon2id, sel, nonce).
- Dérivation de clé Argon2id (512 Mio, 4 itérations, 4 voies par défaut) avec bornes de sécurité au déchiffrement.
- Vecteurs de test du format et de la KDF (référence argon2-cffi), tests de propriété.
- Chiffrement par flux STREAM (XChaCha20-Poly1305, morceaux de 64 Kio, en-tête en AAD) :
  mémoire bornée quelle que soit la taille du fichier ; troncature, réorganisation et
  altération détectées.
- Écriture atomique (fichier temporaire, synchronisation, renommage sans écrasement) :
  jamais de fichier partiel, jamais d'écrasement d'un fichier existant.
- Annulation et suivi de progression à chaque morceau.
- Vecteur de test de fichier complet produit par une implémentation indépendante (libsodium).

### Sécurité
- Correction de RUSTSEC-2026-0385 (`ctutils` ≥ 0.4.4) ; version minimale de Rust : 1.88.
