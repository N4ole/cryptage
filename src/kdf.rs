//! Dérivation de la clé de chiffrement à partir du mot de passe (Argon2id v1.3).

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::format::Header;

/// Taille de la clé XChaCha20-Poly1305 (256 bits).
pub const KEY_LEN: usize = 32;

/// Dérive une clé de 256 bits du mot de passe, du sel et des paramètres de l'en-tête.
///
/// La clé est renvoyée dans un conteneur effacé automatiquement de la mémoire à sa libération.
/// Les paramètres sont revalidés ici pour ne jamais lancer Argon2 avec des valeurs hors limites.
pub fn derive_key(password: &[u8], header: &Header) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if password.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }
    header.kdf.validate()?;
    let params = Params::new(
        header.kdf.m_cost_kib,
        header.kdf.t_cost,
        header.kdf.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::UnsafeParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, &header.salt, key.as_mut())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{DEFAULT_CHUNK_LOG2, KdfParams, NONCE_PREFIX_LEN, SALT_LEN};

    fn header(salt: u8) -> Header {
        Header {
            kdf: KdfParams::MINIMUM,
            salt: [salt; SALT_LEN],
            chunk_log2: DEFAULT_CHUNK_LOG2,
            nonce_prefix: [0; NONCE_PREFIX_LEN],
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Vecteurs Argon2id v1.3 (m=64 Mio, t=3, sel=0x01×16, mot de passe "mot de passe", 32 octets),
    /// calculés indépendamment avec l'implémentation de référence en C (argon2-cffi,
    /// `hash_secret_raw`), pour p=1 et p=4.
    #[test]
    fn vecteurs_de_test_kdf() {
        let mut h = header(1);
        let key = derive_key("mot de passe".as_bytes(), &h).unwrap();
        assert_eq!(
            hex(key.as_ref()),
            "2b7eab70d945ee6c9aa50e4874636a4b467b391bb58852c302b512043434a838"
        );
        h.kdf.p_cost = 4;
        let key = derive_key("mot de passe".as_bytes(), &h).unwrap();
        assert_eq!(
            hex(key.as_ref()),
            "493dfe17f6a6d5ec5cc226d6aa40de2f07df4968f1673060b0e0c7a09adc21cd"
        );
    }

    #[test]
    fn determinisme_et_sensibilite() {
        let a = derive_key(b"abc", &header(1)).unwrap();
        let b = derive_key(b"abc", &header(1)).unwrap();
        let c = derive_key(b"abd", &header(1)).unwrap();
        let d = derive_key(b"abc", &header(2)).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
        assert_ne!(*a, *d);
    }

    #[test]
    fn mot_de_passe_vide_refuse() {
        assert!(matches!(
            derive_key(b"", &header(1)),
            Err(CryptoError::EmptyPassword)
        ));
    }

    #[test]
    fn parametres_faibles_refuses() {
        let mut h = header(1);
        h.kdf.t_cost = 1;
        assert!(matches!(
            derive_key(b"abc", &h),
            Err(CryptoError::UnsafeParameters)
        ));
    }
}
