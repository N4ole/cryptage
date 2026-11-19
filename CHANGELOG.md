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
