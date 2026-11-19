# Contribuer à cryptage

Merci de votre intérêt ! Quelques règles simples.

## Environnement

Rust stable (voir `rust-toolchain.toml`). Pour une chaîne d'outils isolée dans le
projet (sans installation globale) sous Windows :

```powershell
$env:RUSTUP_HOME = "$PWD\.rust\rustup"; $env:CARGO_HOME = "$PWD\.rust\cargo"
# installer rustup-init.exe avec --no-modify-path, puis à chaque session :
. .\scripts\activate.ps1
```

Sous Linux, installez aussi : `libgtk-3-dev libxkbcommon-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev`.

## Avant d'ouvrir une Pull Request

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Flux Git

- Ne poussez jamais directement sur `main` : créez une branche `feat/...`, `fix/...`,
  `docs/...`, `ci/...` ou `chore/...` et ouvrez une Pull Request.
- La CI doit être verte avant fusion.
- Messages de commit au format [Conventional Commits](https://www.conventionalcommits.org/fr/) :
  `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`, `refactor:`.
- Commits atomiques : un changement logique par commit.
- Mettez à jour `CHANGELOG.md` (section `Unreleased`).

## Règles de sécurité

- N'inventez aucune primitive cryptographique ; utilisez les crates RustCrypto.
- Aucun secret (mot de passe, clé) dans les journaux, messages d'erreur ou fichiers.
- Toute modification du format de fichier impose une nouvelle version de format,
  des vecteurs de test et la compatibilité en lecture des anciennes versions.
- Ne committez jamais de fichier `.env`, de secret ni de données réelles.
- Toute nouvelle dépendance doit être justifiée dans le README.
