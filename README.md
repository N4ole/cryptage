# cryptage

[![CI](https://github.com/N4ole/cryptage/actions/workflows/ci.yml/badge.svg)](https://github.com/N4ole/cryptage/actions/workflows/ci.yml)
[![Licence : MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

Application de bureau pour **chiffrer et déchiffrer des fichiers avec un mot de passe**.
Tout fonctionne hors ligne : pas de serveur, pas de compte, pas de connexion internet.
Un fichier chiffré se déchiffre sur n'importe quel appareil (Windows, macOS, Linux) où
l'application est installée, avec le bon mot de passe.

> [!CAUTION]
> **Sans le mot de passe, les données sont définitivement irrécupérables.**
> Il n'existe ni porte dérobée, ni « mot de passe oublié », ni procédure de récupération.
> Conservez votre mot de passe dans un gestionnaire de mots de passe.

## Sommaire

- [Installation](#installation)
- [Utilisation](#utilisation)
- [Choix cryptographiques](#choix-cryptographiques)
- [Format de fichier](#format-de-fichier)
- [Garanties et limites connues](#garanties-et-limites-connues)
- [Dépendances](#dépendances)
- [Développement](#développement)
- [Publier une nouvelle version](#publier-une-nouvelle-version)
- [Licence](#licence)

## Installation

Téléchargez l'archive correspondant à votre système depuis la page
[Releases](https://github.com/N4ole/cryptage/releases) :

| Système                 | Archive                                         |
|-------------------------|-------------------------------------------------|
| Windows (x64)           | `cryptage-vX.Y.Z-x86_64-pc-windows-msvc.zip`    |
| macOS (Apple Silicon)   | `cryptage-vX.Y.Z-aarch64-apple-darwin.tar.gz`   |
| macOS (Intel)           | `cryptage-vX.Y.Z-x86_64-apple-darwin.tar.gz`    |
| Linux (x64, glibc)      | `cryptage-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` |

L'application est un exécutable unique, sans installation : extrayez l'archive et lancez `cryptage`.

### Vérifier le téléchargement

```sh
# Intégrité : comparer avec SHA256SUMS (publié avec la release)
sha256sum -c SHA256SUMS --ignore-missing          # Linux
shasum -a 256 -c SHA256SUMS --ignore-missing      # macOS
# Origine : attestation de provenance GitHub (le binaire a été compilé par la CI de ce dépôt)
gh attestation verify cryptage-vX.Y.Z-<cible>.tar.gz --repo N4ole/cryptage
```

Sous Windows (PowerShell) : `Get-FileHash .\cryptage-vX.Y.Z-x86_64-pc-windows-msvc.zip -Algorithm SHA256`.

Les binaires ne sont pas signés par un certificat commercial. Windows SmartScreen et macOS
Gatekeeper peuvent donc afficher un avertissement au premier lancement. Sous macOS :
clic droit → « Ouvrir », ou `xattr -d com.apple.quarantine cryptage`.

Sous Linux, la boîte de dialogue de choix de fichier utilise le portail XDG
(`xdg-desktop-portal`, présent par défaut sur les bureaux courants). Le glisser-déposer
fonctionne dans tous les cas.

## Utilisation

**Chiffrer**

1. Onglet **Chiffrer**.
2. Choisissez un fichier (bouton ou glisser-déposer).
3. Saisissez le mot de passe, puis confirmez-le. L'indicateur de force vous conseille. Un
   mot de passe faible doit être explicitement accepté.
4. Option : suppression du fichier d'origine après chiffrement (confirmation demandée).
5. **Chiffrer** : `rapport.pdf` donne `rapport.pdf.enc`.

**Déchiffrer**

1. Onglet **Déchiffrer**.
2. Choisissez le fichier `.enc` et saisissez le mot de passe.
3. **Déchiffrer** : `rapport.pdf.enc` donne `rapport.pdf`.

Dans les deux cas :

- un fichier existant n'est **jamais écrasé** : la sortie devient `rapport (1).pdf` si besoin ;
- une barre de progression s'affiche et le bouton **Annuler** reste disponible ;
- la dérivation de la clé prend une à quelques secondes : c'est voulu, c'est ce qui rend les
  attaques par force brute coûteuses.

En cas d'échec, le message est volontairement le même pour un mauvais mot de passe et pour
un fichier altéré : « Échec du déchiffrement : mot de passe incorrect ou fichier altéré. »

**Conseil** : utilisez une phrase de passe d'au moins 5 ou 6 mots choisis au hasard.

## Choix cryptographiques

Uniquement des primitives standard, implémentées par les crates de l'écosystème
[RustCrypto](https://github.com/RustCrypto). Aucune primitive maison.

| Rôle                        | Choix                                     | Justification |
|-----------------------------|-------------------------------------------|---------------|
| Chiffrement authentifié     | **XChaCha20-Poly1305**                    | Clé de 256 bits. Nonce de 192 bits qui peut être tiré au hasard sans risque de collision. Rapide et en temps constant sur toutes les machines, même sans instructions AES matérielles. |
| Mode flux                   | **STREAM** (variante BE32, crate `aead-stream`) | Chiffre de gros fichiers par morceaux authentifiés avec une mémoire bornée. Chaque morceau porte un compteur et un drapeau « dernier morceau » : troncature, réorganisation et duplication sont détectées ([Hoang, Reyhanitabar, Rogaway, Vizár, 2015](https://eprint.iacr.org/2015/189.pdf)). |
| Dérivation de clé           | **Argon2id** v1.3 (RFC 9106)              | Fonction coûteuse en mémoire, résistante aux attaques par GPU ou ASIC. **Paramètres par défaut : 512 Mio, 4 itérations, 4 voies**, soit environ 8 fois le minimum exigé (64 Mio, 3 itérations), pour une sécurité renforcée. |
| Sel                         | 16 octets aléatoires par fichier          | Deux fichiers chiffrés avec le même mot de passe ont des clés différentes. |
| Nonce                       | Préfixe aléatoire de 19 octets par fichier | Clé unique par fichier (grâce au sel) **et** nonce aléatoire : double protection contre la réutilisation de nonce. |
| Aléa                        | Générateur du système (`rand::rngs::SysRng`, ex-`OsRng`) | `getrandom` : `BCryptGenRandom`, `getrandom(2)`, `SecRandomCopyBytes`. |
| Intégrité de l'en-tête      | En-tête complet en AAD de chaque morceau  | Modifier un paramètre, le sel, le nonce ou la version fait échouer le déchiffrement. |
| Effacement des secrets      | `zeroize`                                 | Clé, mot de passe et tampons de texte clair effacés de la mémoire après usage. |

### Points de conception notables

- **Bornes au déchiffrement** : les paramètres Argon2 lus dans un fichier sont bornés
  (64 Mio à 2 Gio, 3 à 32 itérations, 1 à 16 voies). Un fichier piégé ne peut donc pas
  épuiser la mémoire ni affaiblir la dérivation.
- **Pas de fichier partiel** : la sortie est écrite dans un fichier temporaire du même dossier,
  synchronisée sur disque, puis renommée sans écrasement. Toute erreur, y compris une
  altération détectée au dernier morceau, ou une annulation supprime le fichier temporaire.
- **Message d'échec générique** : impossible de distinguer un mauvais mot de passe d'un
  fichier altéré.
- **Aucun stockage** : ni clé, ni mot de passe, ni préférence ne sont enregistrés. La
  persistance d'eframe est désactivée.
- **Nom du fichier d'origine** : il n'est pas stocké dans le fichier chiffré. Le nom de
  sortie est obtenu en retirant `.enc`.

## Format de fichier

Format **versionné** : la version est lue avant tout le reste. Une future version 2 pourra
changer la disposition, et l'application continuera de lire les fichiers v1. Une version
inconnue est refusée avec un message explicite.

### Version 1

Entiers en petit-boutiste. En-tête de 60 octets :

| Décalage | Taille | Champ                                                   |
|---------:|-------:|---------------------------------------------------------|
| 0        | 8      | Marqueur magique `CRYPTAGE` (ASCII)                     |
| 8        | 2      | Version de format = `1`                                 |
| 10       | 1      | KDF = `1` (Argon2id v1.3)                               |
| 11       | 4      | Argon2 `m_cost`, en Kio                                 |
| 15       | 4      | Argon2 `t_cost` (itérations)                            |
| 19       | 4      | Argon2 `p_cost` (voies)                                 |
| 23       | 16     | Sel                                                     |
| 39       | 1      | AEAD = `1` (XChaCha20-Poly1305)                         |
| 40       | 1      | `log2` de la taille des morceaux en clair (`16` = 64 Kio, de 12 à 24 admis) |
| 41       | 19     | Préfixe de nonce STREAM                                 |

Puis le corps : une suite de morceaux `chiffré ‖ étiquette Poly1305 (16 octets)`.

- Clé : `Argon2id(mot de passe UTF-8, sel, m, t, p) → 32 octets`.
- Nonce du morceau *i* : `préfixe (19) ‖ i en grand-boutiste sur 32 bits (4) ‖ drapeau (1)`,
  avec drapeau = `1` pour le dernier morceau et `0` sinon.
- AAD de chaque morceau : les 60 octets bruts de l'en-tête.
- Tous les morceaux font exactement `2^log2` octets en clair, sauf le dernier, qui fait de 0 à
  `2^log2` octets. Un fichier vide produit donc un unique morceau de 16 octets (l'étiquette).
- Le compteur de 32 bits limite un fichier à environ 2^32 morceaux, soit 256 Tio avec des
  morceaux de 64 Kio.

### Vecteurs de test

- [`tests/vectors/v1_reference.enc`](tests/vectors/v1_reference.enc) est produit par une
  **implémentation indépendante** en Python, avec libsodium (via PyNaCl) et l'implémentation
  C de référence d'Argon2 (via argon2-cffi) : [`gen_vector.py`](tests/vectors/gen_vector.py).
  Le moteur Rust doit le déchiffrer, et le rechiffrer octet pour octet.
- Les vecteurs Argon2id (p=1 et p=4) et le vecteur d'en-tête sont figés dans les tests unitaires.

## Garanties et limites connues

**Ce que l'application protège** : la confidentialité et l'intégrité du contenu d'un fichier
au repos ou en transit (clé USB, cloud, courriel), face à quelqu'un qui n'a pas le mot de passe.

**Limites :**

- **Mot de passe** : la sécurité dépend entièrement de lui. Argon2id ralentit les attaques
  par force brute, mais ne peut pas sauver un mot de passe faible.
- **Métadonnées visibles** : le nom du fichier `.enc` (qui reprend le nom d'origine), sa taille
  (proche de celle d'origine) et ses dates ne sont pas cachés. Renommez le fichier si son nom
  est sensible.
- **Suppression de l'original** : il s'agit d'une suppression simple, **pas d'un effacement
  sécurisé**. Sur SSD, clé USB, système de fichiers journalisé, dossier synchronisé (OneDrive,
  Dropbox…) ou sauvegarde, des copies peuvent subsister physiquement.
- **Machine compromise** : un logiciel malveillant ou un enregistreur de frappe sur l'appareil
  peut capturer le mot de passe. Aucun logiciel de chiffrement n'y peut rien.
- **Mémoire** : les secrets sont effacés avec `zeroize`, au mieux. La bibliothèque
  d'interface (egui), le système d'exploitation (fichier d'échange, mise en veille prolongée)
  ou l'estimateur de force (zxcvbn) peuvent conserver des copies temporaires du mot de passe
  saisi. Les champs ont une capacité réservée pour éviter les réallocations.
- **Mémoire requise** : la dérivation de clé utilise 512 Mio de RAM. Sur un appareil avec
  très peu de mémoire, elle peut échouer.
- **Normalisation Unicode** : le mot de passe est utilisé tel quel (UTF-8), sans
  normalisation. Un mot de passe avec des accents saisi sur un système qui produit une autre
  forme Unicode (cas rare, par exemple une saisie en NFD) ne serait pas reconnu. En cas de
  doute, préférez des caractères ASCII.
- **Pas de signature** : le chiffrement garantit que le fichier n'a pas été modifié par
  quelqu'un qui ignore le mot de passe. Il ne prouve pas *qui* l'a chiffré : toute personne
  qui connaît le mot de passe peut produire un fichier valide.
- **Binaires non signés** : avertissements de SmartScreen ou Gatekeeper. Vérifiez SHA256SUMS
  et l'attestation de provenance.
- **Avis « non maintenu »** : `chrono` (via zxcvbn) et `zvariant`, `zbus_names`,
  `zvariant_derive` (via la boîte de dialogue et l'accessibilité sous Linux) sont signalés
  comme non maintenus par RustSec. Aucune vulnérabilité connue, sans lien avec le moteur
  cryptographique. Les exceptions sont documentées dans [`deny.toml`](deny.toml).

## Dépendances

Chaque dépendance est justifiée. Toutes sont sous licence MIT ou Apache-2.0.

| Crate              | Usage | Justification |
|--------------------|-------|---------------|
| `chacha20poly1305` | Moteur | AEAD XChaCha20-Poly1305 de RustCrypto, audité par NCC Group, avec la feature `zeroize`. |
| `aead-stream`      | Moteur | Construction STREAM de RustCrypto (auparavant intégrée à la crate `aead`). |
| `argon2`           | Moteur | Argon2id de RustCrypto. Feature `parallel` (rayon) pour calculer les 4 voies en parallèle, `zeroize` pour effacer la mémoire de travail. |
| `rand`             | Moteur | Accès au générateur aléatoire du système (`SysRng`), feature `sys_rng` uniquement. |
| `zeroize`          | Moteur | Effacement garanti des secrets (non supprimé par l'optimiseur). |
| `thiserror`        | Moteur | Types d'erreur avec messages en français, sans code à la main. |
| `tempfile`         | Fichiers | Fichier temporaire sûr (nom aléatoire, création exclusive) et renommage atomique sans écrasement (`persist_noclobber`). |
| `zxcvbn`           | Interface | Estimation réaliste de la force d'un mot de passe (dictionnaires, motifs clavier, dates), bien meilleure qu'un simple comptage de caractères. |
| `eframe` / `egui`  | Interface | Interface native en mode immédiat, un seul exécutable, sans webview ni navigateur embarqué. Features réduites : `glow`, `x11`, `wayland`, `default_fonts`, `accesskit` (accessibilité). |
| `rfd`              | Interface | Boîtes de dialogue natives (Win32, AppKit, portail XDG). |
| `proptest`         | Tests | Tests de propriété sur le format et le flux. |

## Développement

Voir [CONTRIBUTING.md](CONTRIBUTING.md). En résumé :

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features      # inclut le test de flux de plus de 1 Gio
cargo run --release
```

La CI (GitHub Actions) exécute fmt, clippy, les tests et le build release sous Linux, Windows
et macOS. Elle lance aussi `cargo audit` et `cargo deny` (vulnérabilités, licences, sources)
et mesure la couverture (`cargo llvm-cov`, rapport en artefact). La branche `main` est
protégée : une Pull Request avec une CI verte est obligatoire.

Choix faits par défaut (option la plus sûre et la plus simple) :

- ne jamais écraser un fichier existant ;
- refuser l'empaquetage de dossiers (un fichier à la fois) ;
- exiger une acceptation explicite pour un mot de passe faible ;
- ne pas stocker le nom d'origine dans le fichier chiffré ;
- ne pas normaliser le mot de passe ;
- borner les paramètres Argon2 au déchiffrement.

## Publier une nouvelle version

1. Sur une branche `chore/release-vX.Y.Z` :
   - mettre à jour `version` dans `Cargo.toml` (puis `cargo check` pour mettre à jour `Cargo.lock`) ;
   - dans `CHANGELOG.md`, renommer `## [Unreleased]` en `## [X.Y.Z] - AAAA-MM-JJ` et rouvrir une
     section `## [Unreleased]` vide au-dessus.
2. Ouvrir une Pull Request, attendre la CI verte, fusionner.
3. Créer et pousser le tag sur `main` :

   ```sh
   git checkout main && git pull
   git tag -a vX.Y.Z -m "cryptage vX.Y.Z"
   git push origin vX.Y.Z
   ```

4. Le workflow **Release** vérifie que le tag correspond à `Cargo.toml` et au CHANGELOG, puis
   il lance les tests et compile les 4 cibles. Il publie ensuite les archives, `SHA256SUMS`, les
   attestations de provenance et les notes extraites du CHANGELOG.

## Licence

Distribué sous licence [MIT](LICENSE). Copyright (c) 2026 N4ole.
