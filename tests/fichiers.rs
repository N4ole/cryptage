//! Tests d'intégration sur de vrais fichiers (dossiers temporaires uniquement,
//! aucune donnée réelle).

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use cryptage::CryptoError;
use cryptage::fileops::{decrypt_file, encrypt_file, encrypted_path};
use cryptage::format::{HEADER_LEN, KdfParams};
use cryptage::stream::{self, Control};

const PWD: &[u8] = "correct horse battery staple ✓".as_bytes();
/// Paramètres minimaux admis : suffisent pour les tests et restent rapides.
const P: KdfParams = KdfParams::MINIMUM;

fn no_progress() -> impl FnMut(u64, u64) {
    |_, _| {}
}

fn entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn roundtrip(data: &[u8]) {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("rapport.pdf");
    fs::write(&input, data).unwrap();
    let enc = encrypted_path(&input);
    let cancel = AtomicBool::new(false);
    encrypt_file(&input, &enc, PWD, P, &cancel, &mut no_progress()).unwrap();
    let ct = fs::read(&enc).unwrap();
    assert!(ct.len() > HEADER_LEN);
    if !data.is_empty() {
        assert!(
            !ct.windows(data.len().min(32))
                .any(|w| w == &data[..data.len().min(32)])
        );
    }
    let out = dir.path().join("restaure.pdf");
    decrypt_file(&enc, &out, PWD, &cancel, &mut no_progress()).unwrap();
    assert_eq!(fs::read(&out).unwrap(), data);
    assert_eq!(
        entries(dir.path()),
        ["rapport.pdf", "rapport.pdf.enc", "restaure.pdf"]
    );
}

#[test]
fn aller_retour_fichier_vide() {
    roundtrip(b"");
}

#[test]
fn aller_retour_petit_fichier() {
    roundtrip(b"Bonjour, ceci est un petit fichier de test.\n");
}

#[test]
fn aller_retour_plusieurs_morceaux() {
    let data: Vec<u8> = (0..(3 << 16) + 12345)
        .map(|i| (i * 31 % 256) as u8)
        .collect();
    roundtrip(&data);
}

#[test]
fn parametres_par_defaut() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.txt");
    fs::write(&input, b"donnees").unwrap();
    let cancel = AtomicBool::new(false);
    let enc = dir.path().join("a.txt.enc");
    encrypt_file(
        &input,
        &enc,
        PWD,
        KdfParams::DEFAULT,
        &cancel,
        &mut no_progress(),
    )
    .unwrap();
    let out = dir.path().join("b.txt");
    decrypt_file(&enc, &out, PWD, &cancel, &mut no_progress()).unwrap();
    assert_eq!(fs::read(out).unwrap(), b"donnees");
}

/// Prépare un fichier chiffré et renvoie (dossier, chemin .enc).
fn setup(data: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("f.bin");
    fs::write(&input, data).unwrap();
    let enc = dir.path().join("f.bin.enc");
    let cancel = AtomicBool::new(false);
    encrypt_file(&input, &enc, PWD, P, &cancel, &mut no_progress()).unwrap();
    fs::remove_file(&input).unwrap();
    (dir, enc)
}

/// Tente de déchiffrer et vérifie qu'aucun fichier (sortie ou temporaire) n'est laissé.
fn decrypt_must_fail(dir: &Path, enc: &Path, pwd: &[u8]) -> CryptoError {
    let before = entries(dir);
    let out = dir.join("sortie.bin");
    let cancel = AtomicBool::new(false);
    let err = decrypt_file(enc, &out, pwd, &cancel, &mut no_progress()).unwrap_err();
    assert!(!out.exists(), "fichier déchiffré partiel laissé");
    assert_eq!(entries(dir), before, "fichier temporaire laissé");
    err
}

#[test]
fn mauvais_mot_de_passe() {
    let (dir, enc) = setup(&vec![3u8; 200_000]);
    let err = decrypt_must_fail(dir.path(), &enc, b"mauvais");
    assert!(matches!(err, CryptoError::DecryptionFailed));
    assert_eq!(
        err.to_string(),
        "Échec du déchiffrement : mot de passe incorrect ou fichier altéré."
    );
}

#[test]
fn un_octet_modifie_dans_le_corps() {
    // Le morceau altéré est le dernier : les premiers morceaux valides ont déjà été
    // écrits dans le fichier temporaire, qui doit pourtant disparaître.
    let (dir, enc) = setup(&vec![9u8; 300_000]);
    let mut ct = fs::read(&enc).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x80;
    fs::write(&enc, &ct).unwrap();
    let err = decrypt_must_fail(dir.path(), &enc, PWD);
    assert!(matches!(err, CryptoError::DecryptionFailed));
}

#[test]
fn chaque_octet_de_l_en_tete_modifie() {
    let (dir, enc) = setup(b"contenu");
    let original = fs::read(&enc).unwrap();
    for i in 0..HEADER_LEN {
        let mut ct = original.clone();
        ct[i] ^= 0x01;
        fs::write(&enc, &ct).unwrap();
        let _ = decrypt_must_fail(dir.path(), &enc, PWD);
    }
}

#[test]
fn en_tete_tronque() {
    let (dir, enc) = setup(b"contenu");
    let ct = fs::read(&enc).unwrap();
    fs::write(&enc, &ct[..HEADER_LEN - 5]).unwrap();
    let err = decrypt_must_fail(dir.path(), &enc, PWD);
    assert!(matches!(err, CryptoError::InvalidFormat));
    fs::write(&enc, b"").unwrap();
    let err = decrypt_must_fail(dir.path(), &enc, PWD);
    assert!(matches!(err, CryptoError::InvalidFormat));
}

#[test]
fn version_de_format_inconnue() {
    let (dir, enc) = setup(b"contenu");
    let mut ct = fs::read(&enc).unwrap();
    ct[8..10].copy_from_slice(&99u16.to_le_bytes());
    fs::write(&enc, &ct).unwrap();
    let err = decrypt_must_fail(dir.path(), &enc, PWD);
    assert!(matches!(err, CryptoError::UnsupportedVersion(99)));
}

#[test]
fn fichier_non_chiffre() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("photo.jpg.enc");
    fs::write(&f, b"\xFF\xD8\xFF\xE0 ceci n'est pas un fichier chiffre").unwrap();
    let err = decrypt_must_fail(dir.path(), &f, PWD);
    assert!(matches!(err, CryptoError::InvalidFormat));
}

#[test]
fn destination_existante_jamais_ecrasee() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.txt");
    let enc = dir.path().join("a.txt.enc");
    fs::write(&input, b"nouveau").unwrap();
    fs::write(&enc, b"ancien").unwrap();
    let cancel = AtomicBool::new(false);
    let err = encrypt_file(&input, &enc, PWD, P, &cancel, &mut no_progress()).unwrap_err();
    assert!(matches!(err, CryptoError::OutputExists));
    assert_eq!(fs::read(&enc).unwrap(), b"ancien");
    assert_eq!(entries(dir.path()), ["a.txt", "a.txt.enc"]);
}

#[test]
fn annulation_en_cours_d_operation() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("gros.bin");
    fs::write(&input, vec![0u8; 8 << 20]).unwrap();
    let cancel = AtomicBool::new(false);
    let mut progress = |done: u64, total: u64| {
        assert_eq!(total, 8 << 20);
        if done >= 1 << 20 {
            cancel.store(true, Ordering::Relaxed);
        }
    };
    let enc = dir.path().join("gros.bin.enc");
    let err = encrypt_file(&input, &enc, PWD, P, &cancel, &mut progress).unwrap_err();
    assert!(matches!(err, CryptoError::Cancelled));
    assert_eq!(entries(dir.path()), ["gros.bin"]);
}

#[test]
fn annulation_avant_debut() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.bin");
    fs::write(&input, b"x").unwrap();
    let cancel = AtomicBool::new(true);
    let enc = dir.path().join("a.bin.enc");
    let err = encrypt_file(&input, &enc, PWD, P, &cancel, &mut no_progress()).unwrap_err();
    assert!(matches!(err, CryptoError::Cancelled));
    assert_eq!(entries(dir.path()), ["a.bin"]);
}

// ---------------------------------------------------------------------------
// Test de flux sur plus de 1 Gio, sans fichier sur disque ni chargement en mémoire :
// générateur pseudo-aléatoire → chiffrement → tube → déchiffrement → vérificateur.

const BIG: u64 = (1 << 30) + 12_345;

struct Gen {
    state: u64,
    remaining: u64,
}

impl Gen {
    fn new(remaining: u64) -> Self {
        Self {
            state: 0x9E37_79B9_7F4A_7C15,
            remaining,
        }
    }
    fn next_byte(&mut self) -> u8 {
        // xorshift64*
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        (self.state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
    }
}

impl Read for Gen {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.remaining as usize);
        for b in &mut buf[..n] {
            *b = self.next_byte();
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

struct Verifier {
    expected: Gen,
    seen: u64,
}

impl Write for Verifier {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for &b in buf {
            assert_eq!(
                b,
                self.expected.next_byte(),
                "octet {} différent",
                self.seen
            );
            self.seen += 1;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn flux_de_plus_de_un_gio() {
    let (mut pipe_r, pipe_w) = std::io::pipe().unwrap();
    let producer = std::thread::spawn(move || {
        let cancel = AtomicBool::new(false);
        let mut w = std::io::BufWriter::new(pipe_w);
        stream::encrypt(
            &mut Gen::new(BIG),
            &mut w,
            PWD,
            P,
            &mut Control {
                cancel: &cancel,
                progress: &mut |_| {},
            },
        )
        .unwrap();
    });
    let cancel = AtomicBool::new(false);
    let mut verifier = Verifier {
        expected: Gen::new(BIG),
        seen: 0,
    };
    let mut reader = std::io::BufReader::new(&mut pipe_r);
    stream::decrypt(
        &mut reader,
        &mut verifier,
        PWD,
        &mut Control {
            cancel: &cancel,
            progress: &mut |_| {},
        },
    )
    .unwrap();
    producer.join().unwrap();
    assert_eq!(verifier.seen, BIG);
}
