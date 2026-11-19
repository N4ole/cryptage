//! Moteur de chiffrement de fichiers de `cryptage`.
//!
//! Le moteur est indépendant de l'interface graphique pour être testable seul.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod format;
pub mod kdf;
pub mod stream;

pub use error::{CryptoError, Result};
