//! Chiffrement et déchiffrement par flux (construction STREAM, variante BE32,
//! sur XChaCha20-Poly1305).
//!
//! Le flux est découpé en morceaux de taille fixe (64 Kio par défaut). Chaque morceau
//! est chiffré et authentifié séparément avec un nonce `préfixe(19) ‖ compteur(4) ‖ drapeau_fin(1)`.
//! Le drapeau « dernier morceau » permet de détecter toute troncature, et le compteur
//! toute réorganisation ou duplication. L'en-tête brut est la donnée associée (AAD)
//! de chaque morceau. La mémoire utilisée est bornée par deux morceaux, quelle que
//! soit la taille du fichier.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use aead_stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::array::Array;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::format::{HEADER_LEN, Header, KdfParams, TAG_LEN, read_full};
use crate::kdf::{KEY_LEN, derive_key};

/// Contrôle d'une opération en cours : annulation et suivi de progression.
pub struct Control<'a> {
    /// Passe à `true` pour demander l'annulation (vérifié à chaque morceau).
    pub cancel: &'a AtomicBool,
    /// Appelé après chaque morceau avec le nombre total d'octets lus en entrée.
    pub progress: &'a mut dyn FnMut(u64),
}

impl Control<'_> {
    fn check_cancel(&self) -> Result<()> {
        if self.cancel.load(Ordering::Relaxed) {
            Err(CryptoError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Chiffre `reader` vers `writer` avec un mot de passe et des paramètres Argon2id.
pub fn encrypt<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &[u8],
    params: KdfParams,
    ctl: &mut Control<'_>,
) -> Result<()> {
    let header = Header::new_random(params)?;
    let key = derive_key(password, &header)?;
    ctl.check_cancel()?;
    encrypt_with_key(reader, writer, &header, &key, ctl)
}

/// Déchiffre `reader` vers `writer`. Toute altération ou un mauvais mot de passe
/// produit [`CryptoError::DecryptionFailed`], sans distinction.
///
/// Attention : des morceaux déjà authentifiés peuvent avoir été écrits dans `writer`
/// avant qu'une erreur ne soit détectée plus loin. L'appelant doit donc écrire dans
/// une destination temporaire et la jeter en cas d'erreur (voir [`crate::fileops`]).
pub fn decrypt<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &[u8],
    ctl: &mut Control<'_>,
) -> Result<()> {
    let (header, raw) = Header::read_from(reader)?;
    let key = derive_key(password, &header)?;
    ctl.check_cancel()?;
    decrypt_with_key(reader, writer, &header, &raw, &key, ctl)
}

fn cipher(key: &[u8; KEY_LEN]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::EncryptionFailed)
}

/// Tampon de morceau dont toute la capacité est effacée à la libération.
/// La capacité inclut l'étiquette pour que le chiffrement en place ne réalloue jamais
/// (une réallocation laisserait une copie non effacée en mémoire).
fn chunk_buffer(chunk: usize) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::with_capacity(chunk + TAG_LEN))
}

/// Remplit `buf` avec au plus `len` octets lus ; `buf.len()` vaut ensuite le nombre lu.
fn fill<R: Read>(reader: &mut R, buf: &mut Vec<u8>, len: usize) -> Result<()> {
    buf.resize(len, 0);
    let n = read_full(reader, buf)?;
    buf.truncate(n);
    Ok(())
}

pub(crate) fn encrypt_with_key<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    header: &Header,
    key: &[u8; KEY_LEN],
    ctl: &mut Control<'_>,
) -> Result<()> {
    let aad = header.to_bytes();
    writer.write_all(&aad)?;
    let nonce = Array::from(header.nonce_prefix);
    let mut enc = EncryptorBE32::from_aead(cipher(key)?, &nonce);

    let chunk = header.chunk_size();
    let mut cur = chunk_buffer(chunk);
    let mut next = chunk_buffer(chunk);
    let mut done: u64 = 0;
    fill(reader, &mut cur, chunk)?;
    loop {
        ctl.check_cancel()?;
        // Lecture anticipée : un morceau plein n'est le dernier que si la suite est vide.
        let is_last = if cur.len() < chunk {
            true
        } else {
            fill(reader, &mut next, chunk)?;
            next.is_empty()
        };
        done += cur.len() as u64;
        if is_last {
            enc.encrypt_last_in_place(&aad, &mut *cur)
                .map_err(|_| CryptoError::EncryptionFailed)?;
            writer.write_all(&cur)?;
            (ctl.progress)(done);
            break;
        }
        enc.encrypt_next_in_place(&aad, &mut *cur)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        writer.write_all(&cur)?;
        (ctl.progress)(done);
        std::mem::swap(&mut cur, &mut next);
    }
    writer.flush()?;
    Ok(())
}

pub(crate) fn decrypt_with_key<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    header: &Header,
    aad: &[u8; HEADER_LEN],
    key: &[u8; KEY_LEN],
    ctl: &mut Control<'_>,
) -> Result<()> {
    let nonce = Array::from(header.nonce_prefix);
    let mut dec = DecryptorBE32::from_aead(cipher(key)?, &nonce);

    let ct_chunk = header.chunk_size() + TAG_LEN;
    let mut cur = chunk_buffer(header.chunk_size());
    let mut next = chunk_buffer(header.chunk_size());
    let mut done = HEADER_LEN as u64;
    fill(reader, &mut cur, ct_chunk)?;
    loop {
        ctl.check_cancel()?;
        let is_last = if cur.len() < ct_chunk {
            true
        } else {
            fill(reader, &mut next, ct_chunk)?;
            next.is_empty()
        };
        done += cur.len() as u64;
        if cur.len() < TAG_LEN {
            return Err(CryptoError::DecryptionFailed);
        }
        if is_last {
            dec.decrypt_last_in_place(aad, &mut *cur)
                .map_err(|_| CryptoError::DecryptionFailed)?;
            writer.write_all(&cur)?;
            (ctl.progress)(done);
            break;
        }
        dec.decrypt_next_in_place(aad, &mut *cur)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        writer.write_all(&cur)?;
        (ctl.progress)(done);
        std::mem::swap(&mut cur, &mut next);
    }
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{DEFAULT_CHUNK_LOG2, NONCE_PREFIX_LEN, SALT_LEN};
    use proptest::prelude::*;

    const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];

    fn header(chunk_log2: u8) -> Header {
        Header {
            kdf: KdfParams::MINIMUM,
            salt: [7; SALT_LEN],
            chunk_log2,
            nonce_prefix: [9; NONCE_PREFIX_LEN],
        }
    }

    fn no_cancel() -> AtomicBool {
        AtomicBool::new(false)
    }

    fn enc(data: &[u8], h: &Header) -> Vec<u8> {
        let cancel = no_cancel();
        let mut out = Vec::new();
        encrypt_with_key(
            &mut &data[..],
            &mut out,
            h,
            &KEY,
            &mut Control {
                cancel: &cancel,
                progress: &mut |_| {},
            },
        )
        .unwrap();
        out
    }

    fn dec(data: &[u8]) -> Result<Vec<u8>> {
        let cancel = no_cancel();
        let mut r = data;
        let (h, raw) = Header::read_from(&mut r)?;
        let mut out = Vec::new();
        decrypt_with_key(
            &mut r,
            &mut out,
            &h,
            &raw,
            &KEY,
            &mut Control {
                cancel: &cancel,
                progress: &mut |_| {},
            },
        )?;
        Ok(out)
    }

    /// Vecteur produit par une implémentation indépendante (libsodium + argon2 C),
    /// voir `tests/vectors/gen_vector.py`. On doit le déchiffrer, et le rechiffrer
    /// avec le même en-tête doit redonner exactement les mêmes octets.
    #[test]
    fn vecteur_de_reference_independant() {
        const VECTOR: &[u8] = include_bytes!("../tests/vectors/v1_reference.enc");
        let password = "Bonjour à tous !".as_bytes();
        let expected: Vec<u8> = (0..2 * 4096 + 1000)
            .map(|i: usize| ((i * 7 + 3) % 256) as u8)
            .collect();
        let cancel = no_cancel();
        let mut out = Vec::new();
        decrypt(
            &mut &VECTOR[..],
            &mut out,
            password,
            &mut Control {
                cancel: &cancel,
                progress: &mut |_| {},
            },
        )
        .unwrap();
        assert_eq!(out, expected);

        let (h, _) = Header::read_from(&mut &VECTOR[..]).unwrap();
        let key = derive_key(password, &h).unwrap();
        let mut again = Vec::new();
        encrypt_with_key(
            &mut &expected[..],
            &mut again,
            &h,
            &key,
            &mut Control {
                cancel: &cancel,
                progress: &mut |_| {},
            },
        )
        .unwrap();
        assert_eq!(again, VECTOR);
    }

    #[test]
    fn tailles_aux_frontieres_de_morceaux() {
        let h = header(12); // morceaux de 4 Kio pour tester vite
        let c = h.chunk_size();
        for len in [0, 1, c - 1, c, c + 1, 2 * c, 3 * c + 7] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let ct = enc(&data, &h);
            let chunks = len.div_ceil(c).max(1);
            assert_eq!(ct.len(), HEADER_LEN + len + chunks * TAG_LEN, "len {len}");
            assert_eq!(dec(&ct).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn chaque_octet_modifie_est_detecte() {
        let h = header(12);
        let data: Vec<u8> = (0..(2 * h.chunk_size() + 100)).map(|i| i as u8).collect();
        let ct = enc(&data, &h);
        // Chaque octet de l'en-tête et du corps (la clé est fixe ici : pas d'Argon2).
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 0x01;
            assert!(dec(&bad).is_err(), "octet {i} modifié non détecté");
        }
    }

    #[test]
    fn troncatures_et_ajouts_detectes() {
        let h = header(12);
        let c = h.chunk_size();
        let data = vec![0xAB; 3 * c];
        let ct = enc(&data, &h);
        // Supprimer le dernier morceau entier : la frontière tombe juste, mais le
        // drapeau « dernier » ne correspond pas.
        let without_last = &ct[..ct.len() - (c + TAG_LEN)];
        assert!(matches!(
            dec(without_last),
            Err(CryptoError::DecryptionFailed)
        ));
        for cut in [1, TAG_LEN, TAG_LEN + 1, c] {
            assert!(dec(&ct[..ct.len() - cut]).is_err(), "coupe {cut}");
        }
        assert!(dec(&ct[..HEADER_LEN]).is_err());
        let mut extra = ct.clone();
        extra.push(0);
        assert!(dec(&extra).is_err());
    }

    #[test]
    fn morceaux_permutes_detectes() {
        let h = header(12);
        let c = h.chunk_size() + TAG_LEN;
        let data: Vec<u8> = (0..3 * h.chunk_size()).map(|i| (i / 7) as u8).collect();
        let mut ct = enc(&data, &h);
        let (a, b) = (HEADER_LEN, HEADER_LEN + c);
        let first: Vec<u8> = ct[a..a + c].to_vec();
        let second: Vec<u8> = ct[b..b + c].to_vec();
        ct[a..a + c].copy_from_slice(&second);
        ct[b..b + c].copy_from_slice(&first);
        assert!(matches!(dec(&ct), Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn mauvaise_cle_message_generique() {
        let h = header(DEFAULT_CHUNK_LOG2);
        let ct = enc(b"secret", &h);
        let cancel = no_cancel();
        let mut r = &ct[..];
        let (h, raw) = Header::read_from(&mut r).unwrap();
        let err = decrypt_with_key(
            &mut r,
            &mut Vec::new(),
            &h,
            &raw,
            &[0x43; KEY_LEN],
            &mut Control {
                cancel: &cancel,
                progress: &mut |_| {},
            },
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::DecryptionFailed));
        assert_eq!(
            err.to_string(),
            "Échec du déchiffrement : mot de passe incorrect ou fichier altéré."
        );
    }

    #[test]
    fn annulation_en_cours() {
        let h = header(12);
        let data = vec![1u8; 10 * h.chunk_size()];
        let cancel = AtomicBool::new(false);
        let mut calls = 0;
        let mut out = Vec::new();
        let err = encrypt_with_key(
            &mut &data[..],
            &mut out,
            &h,
            &KEY,
            &mut Control {
                cancel: &cancel,
                progress: &mut |_| {
                    calls += 1;
                    if calls == 2 {
                        cancel.store(true, Ordering::Relaxed);
                    }
                },
            },
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::Cancelled));
        assert_eq!(calls, 2);
    }

    #[test]
    fn progression_monotone_et_complete() {
        let h = header(12);
        let data = vec![5u8; 5 * h.chunk_size() + 3];
        let cancel = no_cancel();
        let mut seen = Vec::new();
        let mut out = Vec::new();
        encrypt_with_key(
            &mut &data[..],
            &mut out,
            &h,
            &KEY,
            &mut Control {
                cancel: &cancel,
                progress: &mut |n| seen.push(n),
            },
        )
        .unwrap();
        assert!(seen.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(*seen.last().unwrap(), data.len() as u64);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn aller_retour_proprietes(
            data in proptest::collection::vec(any::<u8>(), 0..20_000),
            log2 in 12u8..=14,
        ) {
            let h = header(log2);
            let ct = enc(&data, &h);
            prop_assert_eq!(dec(&ct).unwrap(), data);
        }

        #[test]
        fn dechiffrement_sans_panique(
            data in proptest::collection::vec(any::<u8>(), 0..10_000),
            pos in any::<prop::sample::Index>(),
            flip in 1u8..=255,
        ) {
            let h = header(12);
            let mut ct = enc(&data, &h);
            let i = HEADER_LEN + pos.index(ct.len() - HEADER_LEN);
            ct[i] ^= flip;
            prop_assert!(dec(&ct).is_err());
        }
    }
}
