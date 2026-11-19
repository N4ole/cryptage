//! Exécution des opérations longues dans un thread séparé : l'interface ne se fige jamais.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use cryptage::fileops;
use cryptage::format::KdfParams;
use eframe::egui;
use zeroize::Zeroizing;

/// Opération demandée par l'interface.
pub enum Task {
    /// Chiffrer `input` vers `output`, puis éventuellement supprimer `input`.
    Encrypt {
        input: PathBuf,
        output: PathBuf,
        delete_source: bool,
    },
    /// Déchiffrer `input` vers `output`.
    Decrypt { input: PathBuf, output: PathBuf },
}

enum Msg {
    Progress(f32),
    Done(Result<String, String>),
}

/// État observé d'une opération.
pub enum Poll {
    /// En cours ; `None` tant que la clé est en cours de dérivation.
    Running(Option<f32>),
    /// Terminée : message de succès ou d'erreur.
    Finished(Result<String, String>),
}

/// Opération en cours.
pub struct Job {
    rx: Receiver<Msg>,
    cancel: Arc<AtomicBool>,
    progress: Option<f32>,
}

impl Job {
    /// Lance l'opération. Le mot de passe est déplacé dans le thread et effacé à la fin.
    pub fn spawn(task: Task, password: Zeroizing<String>, ctx: egui::Context) -> Self {
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_worker = Arc::clone(&cancel);
        thread::spawn(move || {
            let mut last = -1i32;
            let mut on_progress = |done: u64, total: u64| {
                let permille = done
                    .saturating_mul(1000)
                    .checked_div(total)
                    .map_or(1000, |v| v.min(1000)) as i32;
                if permille != last {
                    last = permille;
                    let _ = tx.send(Msg::Progress(permille as f32 / 1000.0));
                    ctx.request_repaint();
                }
            };
            let result = run(task, password.as_bytes(), &cancel_worker, &mut on_progress);
            drop(password);
            let _ = tx.send(Msg::Done(result));
            ctx.request_repaint();
        });
        Self {
            rx,
            cancel,
            progress: None,
        }
    }

    /// Demande l'annulation (prise en compte au prochain morceau).
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Vrai si l'annulation a été demandée.
    pub fn cancelling(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Relève les messages du thread.
    pub fn poll(&mut self) -> Poll {
        loop {
            match self.rx.try_recv() {
                Ok(Msg::Progress(p)) => self.progress = Some(p),
                Ok(Msg::Done(r)) => return Poll::Finished(r),
                Err(TryRecvError::Empty) => return Poll::Running(self.progress),
                Err(TryRecvError::Disconnected) => {
                    return Poll::Finished(Err("Erreur interne inattendue.".into()));
                }
            }
        }
    }
}

fn file_name(p: &std::path::Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

fn run(
    task: Task,
    password: &[u8],
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<String, String> {
    match task {
        Task::Encrypt {
            input,
            output,
            delete_source,
        } => {
            fileops::encrypt_file(
                &input,
                &output,
                password,
                KdfParams::DEFAULT,
                cancel,
                progress,
            )
            .map_err(|e| e.to_string())?;
            let mut msg = format!("Fichier chiffré avec succès : {}", file_name(&output));
            if delete_source {
                match fileops::remove_source(&input) {
                    Ok(()) => msg.push_str("\nLe fichier d'origine a été supprimé."),
                    Err(e) => msg.push_str(&format!(
                        "\nAttention : le fichier d'origine n'a pas pu être supprimé : {e}"
                    )),
                }
            }
            Ok(msg)
        }
        Task::Decrypt { input, output } => {
            fileops::decrypt_file(&input, &output, password, cancel, progress)
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "Fichier déchiffré avec succès : {}",
                file_name(&output)
            ))
        }
    }
}
