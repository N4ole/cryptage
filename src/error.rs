//! Erreurs du moteur, avec des messages en français destinés à l'utilisateur.
//!
//! Règle de sécurité : aucun message ne contient de secret (mot de passe, clé)
//! et un échec d'authentification produit toujours le même message générique,
//! qu'il soit dû à un mauvais mot de passe ou à un fichier altéré.

use std::io;

/// Erreur renvoyée par le moteur de chiffrement.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Erreur d'entrée/sortie (lecture ou écriture de fichier).
    #[error("Erreur de lecture ou d'écriture : {0}")]
    Io(#[from] io::Error),

    /// Le fichier ne commence pas par un en-tête valide (marqueur absent, en-tête tronqué…).
    #[error("Ce fichier n'est pas un fichier chiffré par cryptage, ou son en-tête est endommagé.")]
    InvalidFormat,

    /// Le fichier a été produit par une version de format inconnue.
    #[error(
        "Version de format {0} non prise en charge : mettez à jour l'application ou vérifiez le fichier."
    )]
    UnsupportedVersion(u16),

    /// Les paramètres de dérivation de clé de l'en-tête sont hors des limites admises.
    #[error(
        "Paramètres de sécurité du fichier hors limites : fichier altéré ou non pris en charge."
    )]
    UnsafeParameters,

    /// Échec d'authentification : mauvais mot de passe OU fichier altéré (volontairement indiscernables).
    #[error("Échec du déchiffrement : mot de passe incorrect ou fichier altéré.")]
    DecryptionFailed,

    /// Échec interne du chiffrement (ne devrait pas se produire).
    #[error("Échec du chiffrement.")]
    EncryptionFailed,

    /// Échec de la dérivation de clé (mémoire insuffisante, paramètres refusés…).
    #[error("Échec de la dérivation de la clé (mémoire insuffisante ?).")]
    Kdf,

    /// Le générateur aléatoire du système est indisponible.
    #[error("Le générateur aléatoire du système est indisponible.")]
    Rng,

    /// Le mot de passe est vide.
    #[error("Le mot de passe ne peut pas être vide.")]
    EmptyPassword,

    /// L'opération a été annulée par l'utilisateur.
    #[error("Opération annulée.")]
    Cancelled,
}

/// Alias de résultat du moteur.
pub type Result<T> = std::result::Result<T, CryptoError>;
