//! Format de fichier chiffré, version 1.
//!
//! Disposition de l'en-tête (entiers en petit-boutiste, 60 octets au total) :
//!
//! | Décalage | Taille | Champ                                         |
//! |---------:|-------:|-----------------------------------------------|
//! | 0        | 8      | marqueur magique `CRYPTAGE`                   |
//! | 8        | 2      | version de format (`1`)                       |
//! | 10       | 1      | identifiant KDF (`1` = Argon2id v1.3)         |
//! | 11       | 4      | Argon2 `m_cost` en Kio                        |
//! | 15       | 4      | Argon2 `t_cost` (itérations)                  |
//! | 19       | 4      | Argon2 `p_cost` (parallélisme)                |
//! | 23       | 16     | sel aléatoire                                 |
//! | 39       | 1      | identifiant AEAD (`1` = XChaCha20-Poly1305)   |
//! | 40       | 1      | log2 de la taille des morceaux en clair       |
//! | 41       | 19     | préfixe de nonce STREAM aléatoire             |
//!
//! L'en-tête complet (octets bruts) est utilisé comme donnée associée (AAD)
//! de chaque morceau chiffré : toute modification est détectée.

use std::io::Read;

use rand::rand_core::TryRng;
use rand::rngs::SysRng;

use crate::error::{CryptoError, Result};

/// Marqueur magique en début de fichier.
pub const MAGIC: [u8; 8] = *b"CRYPTAGE";
/// Version de format produite par cette version de l'application.
pub const FORMAT_VERSION: u16 = 1;
/// Taille de l'en-tête v1 en octets.
pub const HEADER_LEN: usize = 60;
/// Taille du sel Argon2id.
pub const SALT_LEN: usize = 16;
/// Taille du préfixe de nonce STREAM (nonce XChaCha20 de 24 octets moins 5 octets de compteur/drapeau).
pub const NONCE_PREFIX_LEN: usize = 19;
/// Taille de l'étiquette d'authentification Poly1305.
pub const TAG_LEN: usize = 16;
/// Identifiant de KDF : Argon2id (version 0x13).
pub const KDF_ARGON2ID: u8 = 1;
/// Identifiant d'AEAD : XChaCha20-Poly1305.
pub const AEAD_XCHACHA20POLY1305: u8 = 1;
/// Taille des morceaux par défaut : 2^16 = 64 Kio.
pub const DEFAULT_CHUNK_LOG2: u8 = 16;
/// Bornes admises pour la taille des morceaux (4 Kio à 16 Mio).
pub const CHUNK_LOG2_RANGE: std::ops::RangeInclusive<u8> = 12..=24;

/// Paramètres Argon2id stockés dans l'en-tête.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Mémoire en Kio.
    pub m_cost_kib: u32,
    /// Nombre d'itérations.
    pub t_cost: u32,
    /// Degré de parallélisme (voies).
    pub p_cost: u32,
}

impl KdfParams {
    /// Paramètres utilisés pour tout nouveau fichier : 512 Mio, 4 itérations, 4 voies.
    pub const DEFAULT: Self = Self {
        m_cost_kib: 512 * 1024,
        t_cost: 4,
        p_cost: 4,
    };

    /// Plancher de sécurité accepté au déchiffrement : 64 Mio, 3 itérations.
    pub const MINIMUM: Self = Self {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };

    /// Mémoire maximale acceptée (2 Gio), pour qu'un en-tête piégé ne puisse pas épuiser la RAM.
    pub const MAX_M_COST_KIB: u32 = 2 * 1024 * 1024;
    /// Nombre d'itérations maximal accepté.
    pub const MAX_T_COST: u32 = 32;
    /// Parallélisme maximal accepté.
    pub const MAX_P_COST: u32 = 16;

    /// Vérifie que les paramètres sont dans les bornes de sécurité.
    pub fn validate(&self) -> Result<()> {
        let ok = (Self::MINIMUM.m_cost_kib..=Self::MAX_M_COST_KIB).contains(&self.m_cost_kib)
            && (Self::MINIMUM.t_cost..=Self::MAX_T_COST).contains(&self.t_cost)
            && (Self::MINIMUM.p_cost..=Self::MAX_P_COST).contains(&self.p_cost);
        if ok {
            Ok(())
        } else {
            Err(CryptoError::UnsafeParameters)
        }
    }
}

/// En-tête d'un fichier chiffré.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Paramètres Argon2id.
    pub kdf: KdfParams,
    /// Sel aléatoire propre au fichier.
    pub salt: [u8; SALT_LEN],
    /// log2 de la taille des morceaux en clair.
    pub chunk_log2: u8,
    /// Préfixe de nonce STREAM aléatoire.
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

/// Remplit un tampon avec le générateur aléatoire cryptographique du système d'exploitation.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    SysRng.try_fill_bytes(buf).map_err(|_| CryptoError::Rng)
}

impl Header {
    /// Crée un en-tête neuf avec sel et préfixe de nonce aléatoires.
    pub fn new_random(kdf: KdfParams) -> Result<Self> {
        kdf.validate()?;
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        fill_random(&mut salt)?;
        fill_random(&mut nonce_prefix)?;
        Ok(Self {
            kdf,
            salt,
            chunk_log2: DEFAULT_CHUNK_LOG2,
            nonce_prefix,
        })
    }

    /// Taille d'un morceau en clair, en octets.
    pub fn chunk_size(&self) -> usize {
        1usize << self.chunk_log2
    }

    /// Sérialise l'en-tête.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..8].copy_from_slice(&MAGIC);
        out[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        out[10] = KDF_ARGON2ID;
        out[11..15].copy_from_slice(&self.kdf.m_cost_kib.to_le_bytes());
        out[15..19].copy_from_slice(&self.kdf.t_cost.to_le_bytes());
        out[19..23].copy_from_slice(&self.kdf.p_cost.to_le_bytes());
        out[23..39].copy_from_slice(&self.salt);
        out[39] = AEAD_XCHACHA20POLY1305;
        out[40] = self.chunk_log2;
        out[41..60].copy_from_slice(&self.nonce_prefix);
        out
    }

    /// Analyse strictement un en-tête. `bytes` peut être plus court que [`HEADER_LEN`]
    /// (fichier tronqué), auquel cas une erreur est renvoyée.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 10 || bytes[0..8] != MAGIC {
            return Err(CryptoError::InvalidFormat);
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != FORMAT_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }
        if bytes.len() < HEADER_LEN {
            return Err(CryptoError::InvalidFormat);
        }
        if bytes[10] != KDF_ARGON2ID || bytes[39] != AEAD_XCHACHA20POLY1305 {
            return Err(CryptoError::InvalidFormat);
        }
        let u32_at =
            |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let kdf = KdfParams {
            m_cost_kib: u32_at(11),
            t_cost: u32_at(15),
            p_cost: u32_at(19),
        };
        kdf.validate()?;
        let chunk_log2 = bytes[40];
        if !CHUNK_LOG2_RANGE.contains(&chunk_log2) {
            return Err(CryptoError::InvalidFormat);
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[23..39]);
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        nonce_prefix.copy_from_slice(&bytes[41..60]);
        Ok(Self {
            kdf,
            salt,
            chunk_log2,
            nonce_prefix,
        })
    }

    /// Lit et analyse l'en-tête depuis un flux. Renvoie aussi les octets bruts,
    /// à utiliser tels quels comme donnée associée (AAD).
    pub fn read_from<R: Read>(reader: &mut R) -> Result<(Self, [u8; HEADER_LEN])> {
        let mut raw = [0u8; HEADER_LEN];
        let n = read_full(reader, &mut raw)?;
        let header = Self::from_bytes(&raw[..n])?;
        Ok((header, raw))
    }
}

/// Lit jusqu'à remplir `buf` ou atteindre la fin du flux. Renvoie le nombre d'octets lus.
pub(crate) fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample() -> Header {
        Header {
            kdf: KdfParams::DEFAULT,
            salt: [0x11; SALT_LEN],
            chunk_log2: DEFAULT_CHUNK_LOG2,
            nonce_prefix: [0x22; NONCE_PREFIX_LEN],
        }
    }

    /// Vecteur de test figé du format v1 : toute modification involontaire du format le cassera.
    const SAMPLE_HEX: &str = concat!(
        "4352595054414745", // "CRYPTAGE"
        "0100",             // version 1
        "01",               // Argon2id
        "00000800",         // m_cost = 524288 Kio
        "04000000",         // t_cost = 4
        "04000000",         // p_cost = 4
        "11111111111111111111111111111111",
        "01", // XChaCha20-Poly1305
        "10", // 2^16
        "22222222222222222222222222222222222222",
    );

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn vecteur_de_test_v1() {
        assert_eq!(hex(&sample().to_bytes()), SAMPLE_HEX);
        assert_eq!(Header::from_bytes(&sample().to_bytes()).unwrap(), sample());
    }

    #[test]
    fn parametres_par_defaut_valides() {
        KdfParams::DEFAULT.validate().unwrap();
        KdfParams::MINIMUM.validate().unwrap();
        const { assert!(KdfParams::DEFAULT.m_cost_kib >= 64 * 1024) };
        const { assert!(KdfParams::DEFAULT.t_cost >= 3) };
    }

    #[test]
    fn en_tete_aleatoire_unique() {
        let a = Header::new_random(KdfParams::DEFAULT).unwrap();
        let b = Header::new_random(KdfParams::DEFAULT).unwrap();
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce_prefix, b.nonce_prefix);
    }

    #[test]
    fn en_tete_tronque() {
        let bytes = sample().to_bytes();
        for len in 0..HEADER_LEN {
            let err = Header::from_bytes(&bytes[..len]).unwrap_err();
            assert!(matches!(err, CryptoError::InvalidFormat), "longueur {len}");
        }
        let err = Header::read_from(&mut &bytes[..30]).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidFormat));
    }

    #[test]
    fn version_inconnue() {
        let mut bytes = sample().to_bytes();
        bytes[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(CryptoError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn marqueur_invalide() {
        let mut bytes = sample().to_bytes();
        bytes[0] = b'X';
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(CryptoError::InvalidFormat)
        ));
    }

    #[test]
    fn algorithmes_inconnus_refuses() {
        for idx in [10, 39] {
            let mut bytes = sample().to_bytes();
            bytes[idx] = 99;
            assert!(matches!(
                Header::from_bytes(&bytes),
                Err(CryptoError::InvalidFormat)
            ));
        }
    }

    #[test]
    fn parametres_kdf_hors_limites() {
        let cases = [
            (KdfParams::MINIMUM.m_cost_kib - 1, 3, 1),
            (KdfParams::MAX_M_COST_KIB + 1, 3, 1),
            (65536, 2, 1),
            (65536, KdfParams::MAX_T_COST + 1, 1),
            (65536, 3, 0),
            (65536, 3, KdfParams::MAX_P_COST + 1),
        ];
        for (m, t, p) in cases {
            let mut bytes = sample().to_bytes();
            bytes[11..15].copy_from_slice(&u32::to_le_bytes(m));
            bytes[15..19].copy_from_slice(&u32::to_le_bytes(t));
            bytes[19..23].copy_from_slice(&u32::to_le_bytes(p));
            assert!(
                matches!(
                    Header::from_bytes(&bytes),
                    Err(CryptoError::UnsafeParameters)
                ),
                "({m}, {t}, {p})"
            );
        }
    }

    #[test]
    fn taille_de_morceau_hors_limites() {
        for log2 in [0u8, 11, 25, 255] {
            let mut bytes = sample().to_bytes();
            bytes[40] = log2;
            assert!(matches!(
                Header::from_bytes(&bytes),
                Err(CryptoError::InvalidFormat)
            ));
        }
    }

    proptest! {
        #[test]
        fn aller_retour_en_tete(
            m in KdfParams::MINIMUM.m_cost_kib..=KdfParams::MAX_M_COST_KIB,
            t in KdfParams::MINIMUM.t_cost..=KdfParams::MAX_T_COST,
            p in 1u32..=KdfParams::MAX_P_COST,
            salt in any::<[u8; SALT_LEN]>(),
            log2 in CHUNK_LOG2_RANGE,
            nonce in any::<[u8; NONCE_PREFIX_LEN]>(),
        ) {
            let h = Header { kdf: KdfParams { m_cost_kib: m, t_cost: t, p_cost: p }, salt, chunk_log2: log2, nonce_prefix: nonce };
            let bytes = h.to_bytes();
            prop_assert_eq!(Header::from_bytes(&bytes).unwrap(), h.clone());
            let (parsed, raw) = Header::read_from(&mut &bytes[..]).unwrap();
            prop_assert_eq!(parsed, h);
            prop_assert_eq!(raw, bytes);
        }

        #[test]
        fn analyse_sans_panique(data in proptest::collection::vec(any::<u8>(), 0..128)) {
            let _ = Header::from_bytes(&data);
        }
    }
}
