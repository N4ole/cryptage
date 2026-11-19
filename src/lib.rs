//! Moteur de chiffrement de fichiers de `cryptage`.
//!
//! Le moteur est indépendant de l'interface graphique pour être testable seul.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::{CryptoError, Result};
