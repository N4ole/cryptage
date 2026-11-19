//! Opérations sur fichiers : écriture atomique, choix des noms de sortie,
//! suppression optionnelle du fichier source.

use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use crate::error::{CryptoError, Result};
use crate::format::KdfParams;
use crate::stream::{self, Control};

/// Extension ajoutée aux fichiers chiffrés.
pub const EXTENSION: &str = "enc";

/// Taille des tampons d'entrée/sortie.
const IO_BUF: usize = 1 << 20;

/// Chemin de sortie proposé pour chiffrer `input` : `rapport.pdf` → `rapport.pdf.enc`.
pub fn encrypted_path(input: &Path) -> PathBuf {
    let mut name: OsString = input.as_os_str().to_owned();
    name.push(".");
    name.push(EXTENSION);
    PathBuf::from(name)
}

/// Chemin de sortie proposé pour déchiffrer `input` : `rapport.pdf.enc` → `rapport.pdf`.
/// Si le fichier ne se termine pas par `.enc`, ajoute `.dechiffre`.
pub fn decrypted_path(input: &Path) -> PathBuf {
    match input.extension() {
        Some(ext) if ext.eq_ignore_ascii_case(EXTENSION) => input.with_extension(""),
        _ => {
            let mut name: OsString = input.as_os_str().to_owned();
            name.push(".dechiffre");
            PathBuf::from(name)
        }
    }
}

/// Renvoie `path` s'il n'existe pas, sinon `nom (1).ext`, `nom (2).ext`, etc.
pub fn unique_path(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let ext = path.extension().map(|e| e.to_string_lossy());
    for i in 1.. {
        let name = match &ext {
            Some(e) => format!("{stem} ({i}).{e}"),
            None => format!("{stem} ({i})"),
        };
        let candidate = path.with_file_name(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}

/// Écrit `output` de façon atomique : écriture dans un fichier temporaire du même
/// dossier, synchronisation sur disque, puis renommage sans écrasement.
/// En cas d'erreur ou d'annulation, le fichier temporaire est supprimé et `output`
/// n'est jamais créé : aucun fichier partiel ne subsiste.
fn atomic_write<F>(output: &Path, write: F) -> Result<()>
where
    F: FnOnce(&mut BufWriter<&mut File>) -> Result<()>,
{
    if output.exists() {
        return Err(CryptoError::OutputExists);
    }
    let dir = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut tmp = tempfile::Builder::new()
        .prefix(".cryptage-")
        .suffix(".tmp")
        .tempfile_in(dir)?;
    {
        let mut w = BufWriter::with_capacity(IO_BUF, tmp.as_file_mut());
        write(&mut w)?;
        w.flush()?;
    }
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(output).map_err(|e| {
        if e.error.kind() == std::io::ErrorKind::AlreadyExists {
            CryptoError::OutputExists
        } else {
            CryptoError::Io(e.error)
        }
    })?;
    Ok(())
}

/// Chiffre le fichier `input` vers `output` (qui ne doit pas exister).
/// `progress` reçoit (octets traités, taille totale).
pub fn encrypt_file(
    input: &Path,
    output: &Path,
    password: &[u8],
    params: KdfParams,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<()> {
    let file = File::open(input)?;
    let total = file.metadata()?.len();
    let mut reader = BufReader::with_capacity(IO_BUF, file);
    let mut on_progress = |n| progress(n, total);
    atomic_write(output, |w| {
        stream::encrypt(
            &mut reader,
            w,
            password,
            params,
            &mut Control {
                cancel,
                progress: &mut on_progress,
            },
        )
    })
}

/// Déchiffre le fichier `input` vers `output` (qui ne doit pas exister).
/// `progress` reçoit (octets traités, taille totale).
pub fn decrypt_file(
    input: &Path,
    output: &Path,
    password: &[u8],
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<()> {
    let file = File::open(input)?;
    let total = file.metadata()?.len();
    let mut reader = BufReader::with_capacity(IO_BUF, file);
    let mut on_progress = |n| progress(n, total);
    atomic_write(output, |w| {
        stream::decrypt(
            &mut reader,
            w,
            password,
            &mut Control {
                cancel,
                progress: &mut on_progress,
            },
        )
    })
}

/// Supprime le fichier source (suppression simple du système de fichiers).
///
/// ⚠️ Ce n'est PAS un effacement sécurisé : sur SSD, clé USB, système de fichiers
/// journalisé ou dossier synchronisé (OneDrive, Dropbox…), des copies des données
/// peuvent subsister physiquement.
pub fn remove_source(path: &Path) -> Result<()> {
    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noms_de_sortie() {
        assert_eq!(
            encrypted_path(Path::new("dossier/rapport.pdf")),
            PathBuf::from("dossier/rapport.pdf.enc")
        );
        assert_eq!(
            decrypted_path(Path::new("dossier/rapport.pdf.enc")),
            PathBuf::from("dossier/rapport.pdf")
        );
        assert_eq!(
            decrypted_path(Path::new("rapport.pdf.ENC")),
            PathBuf::from("rapport.pdf")
        );
        assert_eq!(
            decrypted_path(Path::new("archive.bin")),
            PathBuf::from("archive.bin.dechiffre")
        );
    }

    #[test]
    fn nom_unique() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.txt");
        assert_eq!(unique_path(&p), p);
        std::fs::write(&p, b"x").unwrap();
        assert_eq!(unique_path(&p), dir.path().join("a (1).txt"));
        std::fs::write(dir.path().join("a (1).txt"), b"x").unwrap();
        assert_eq!(unique_path(&p), dir.path().join("a (2).txt"));
    }
}
