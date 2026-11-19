//! Interface graphique (egui).

mod worker;

use std::path::{Path, PathBuf};

use cryptage::fileops;
use cryptage::password::{self, Strength};
use eframe::egui::{self, Color32, RichText};
use zeroize::{Zeroize, Zeroizing};

use worker::{Job, Poll, Task};

/// Capacité réservée aux champs de mot de passe : évite les réallocations pendant la
/// saisie (une réallocation laisserait une copie non effacée en mémoire).
const PWD_CAPACITY: usize = 256;

const OK: Color32 = Color32::from_rgb(0x2e, 0x9e, 0x4f);
const ERR: Color32 = Color32::from_rgb(0xd9, 0x3f, 0x3f);
const WARN: Color32 = Color32::from_rgb(0xe0, 0x8e, 0x0b);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Encrypt,
    Decrypt,
}

enum Status {
    Success(String),
    Error(String),
}

/// État de l'application. Rien n'est persisté sur disque.
pub struct App {
    mode: Mode,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
    show_password: bool,
    strength: Option<Strength>,
    accept_weak: bool,
    delete_source: bool,
    confirm_delete_open: bool,
    job: Option<Job>,
    status: Option<Status>,
}

fn secret_field() -> Zeroizing<String> {
    Zeroizing::new(String::with_capacity(PWD_CAPACITY))
}

impl Default for App {
    fn default() -> Self {
        Self {
            mode: Mode::Encrypt,
            input: None,
            output: None,
            password: secret_field(),
            confirm: secret_field(),
            show_password: false,
            strength: None,
            accept_weak: false,
            delete_source: false,
            confirm_delete_open: false,
            job: None,
            status: None,
        }
    }
}

impl App {
    fn clear_secrets(&mut self) {
        self.password.zeroize();
        self.confirm.zeroize();
        self.show_password = false;
        self.strength = None;
        self.accept_weak = false;
    }

    fn set_mode(&mut self, mode: Mode) {
        if self.mode != mode {
            self.mode = mode;
            self.clear_secrets();
            self.delete_source = false;
            self.status = None;
            self.refresh_output();
        }
    }

    fn set_input(&mut self, path: PathBuf) {
        if path.is_file() {
            self.input = Some(path);
            self.status = None;
        } else {
            self.input = None;
            self.status = Some(Status::Error(
                "Veuillez choisir un fichier (les dossiers ne sont pas pris en charge).".into(),
            ));
        }
        self.refresh_output();
    }

    fn refresh_output(&mut self) {
        self.output = self.input.as_deref().map(|p| match self.mode {
            Mode::Encrypt => fileops::unique_path(&fileops::encrypted_path(p)),
            Mode::Decrypt => fileops::unique_path(&fileops::decrypted_path(p)),
        });
    }

    fn busy(&self) -> bool {
        self.job.is_some()
    }

    fn can_start(&self) -> bool {
        if self.busy() || self.input.is_none() || self.password.is_empty() {
            return false;
        }
        match self.mode {
            Mode::Decrypt => true,
            Mode::Encrypt => {
                *self.password == *self.confirm
                    && (self.accept_weak || self.strength.as_ref().is_some_and(|s| !s.weak))
            }
        }
    }

    fn start(&mut self, ctx: &egui::Context) {
        let (Some(input), Some(output)) = (self.input.clone(), self.output.clone()) else {
            return;
        };
        let task = match self.mode {
            Mode::Encrypt => Task::Encrypt {
                input,
                output,
                delete_source: self.delete_source,
            },
            Mode::Decrypt => Task::Decrypt { input, output },
        };
        // Le tampon du mot de passe est déplacé (sans copie) vers le thread de travail.
        let password = std::mem::replace(&mut self.password, secret_field());
        self.clear_secrets();
        self.status = None;
        self.job = Some(Job::spawn(task, password, ctx.clone()));
    }

    fn handle_drop(&mut self, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        let dropped = ctx.input(|i| i.raw.dropped_files.first().map(|f| f.path().to_path_buf()));
        if let Some(path) = dropped {
            self.set_input(path);
        }
    }

    fn poll_job(&mut self) -> Option<Option<f32>> {
        let job = self.job.as_mut()?;
        match job.poll() {
            Poll::Running(p) => Some(p),
            Poll::Finished(result) => {
                self.job = None;
                self.status = Some(match result {
                    Ok(msg) => {
                        self.input = None;
                        self.delete_source = false;
                        Status::Success(msg)
                    }
                    Err(msg) => Status::Error(msg),
                });
                self.refresh_output();
                None
            }
        }
    }

    fn file_section(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.busy(), egui::Button::new("Choisir un fichier…"))
                .clicked()
            {
                let mut dialog = rfd::FileDialog::new().set_title("Choisir un fichier");
                if self.mode == Mode::Decrypt {
                    dialog = dialog
                        .add_filter("Fichiers chiffrés (.enc)", &["enc"])
                        .add_filter("Tous les fichiers", &["*"]);
                }
                if let Some(path) = dialog.pick_file() {
                    self.set_input(path);
                }
            }
            ui.label(RichText::new("ou glissez-déposez un fichier dans la fenêtre").weak());
        });
        match &self.input {
            Some(p) => {
                ui.label(format!("Fichier : {}", p.display()));
                if self.mode == Mode::Encrypt && has_enc_extension(p) {
                    ui.colored_label(
                        WARN,
                        "Ce fichier semble déjà chiffré : vouliez-vous utiliser l'onglet « Déchiffrer » ?",
                    );
                }
            }
            None => {
                ui.label(RichText::new("Aucun fichier sélectionné.").italics());
            }
        }
        if let Some(out) = &self.output {
            ui.label(format!("Fichier produit : {}", out.display()));
        }
    }

    fn password_section(&mut self, ui: &mut egui::Ui) {
        let enabled = !self.busy();
        ui.add_space(8.0);
        ui.label("Mot de passe :");
        let resp = ui.add_enabled(
            enabled,
            egui::TextEdit::singleline(&mut *self.password)
                .password(!self.show_password)
                .char_limit(PWD_CAPACITY / 4)
                .desired_width(f32::INFINITY),
        );
        if resp.changed() && self.mode == Mode::Encrypt {
            self.strength = Some(password::evaluate(&self.password));
            self.accept_weak = false;
        }
        if self.mode == Mode::Encrypt {
            ui.label("Confirmation du mot de passe :");
            ui.add_enabled(
                enabled,
                egui::TextEdit::singleline(&mut *self.confirm)
                    .password(!self.show_password)
                    .char_limit(PWD_CAPACITY / 4)
                    .desired_width(f32::INFINITY),
            );
        }
        ui.add_enabled(
            enabled,
            egui::Checkbox::new(&mut self.show_password, "Afficher le mot de passe"),
        );

        if self.mode == Mode::Encrypt {
            if !self.confirm.is_empty() && *self.password != *self.confirm {
                ui.colored_label(ERR, "Les deux mots de passe ne correspondent pas.");
            }
            if let Some(s) = &self.strength
                && !self.password.is_empty()
            {
                let color = match s.score {
                    0 | 1 => ERR,
                    2 => WARN,
                    _ => OK,
                };
                ui.add(
                    egui::ProgressBar::new((s.score as f32 + 1.0) / 5.0)
                        .fill(color)
                        .text(format!("Force : {}", s.label)),
                );
                for hint in &s.hints {
                    ui.label(RichText::new(format!("- {hint}")).small());
                }
                if s.weak {
                    ui.colored_label(
                        ERR,
                        "Mot de passe faible : il pourrait être deviné par une attaque par force brute.",
                    );
                    ui.add_enabled(
                        enabled,
                        egui::Checkbox::new(
                            &mut self.accept_weak,
                            "J'accepte le risque et veux utiliser ce mot de passe faible",
                        ),
                    );
                }
            }
        }
    }

    fn options_section(&mut self, ui: &mut egui::Ui) {
        if self.mode == Mode::Encrypt {
            ui.add_space(8.0);
            ui.add_enabled(
                !self.busy(),
                egui::Checkbox::new(
                    &mut self.delete_source,
                    "Supprimer le fichier d'origine après chiffrement",
                ),
            );
            if self.delete_source {
                ui.colored_label(
                    WARN,
                    "Suppression simple : l'effacement sécurisé n'est PAS garanti \
                     (SSD, clé USB, dossiers synchronisés, sauvegardes…).",
                );
            }
        }
        ui.add_space(8.0);
        ui.label(
            RichText::new(
                "Attention : sans le mot de passe, les données chiffrées sont définitivement irrécupérables.",
            )
            .strong(),
        );
    }

    fn action_section(&mut self, ui: &mut egui::Ui, progress: Option<Option<f32>>) {
        ui.add_space(10.0);
        if let Some(p) = progress {
            let cancelling = self.job.as_ref().is_some_and(Job::cancelling);
            match p {
                None => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Dérivation de la clé (Argon2id, 512 Mio)…");
                    });
                }
                Some(f) => {
                    ui.add(egui::ProgressBar::new(f).show_percentage().animate(true));
                }
            }
            let label = if cancelling {
                "Annulation…"
            } else {
                "Annuler"
            };
            if ui
                .add_enabled(!cancelling, egui::Button::new(label))
                .clicked()
                && let Some(job) = &self.job
            {
                job.cancel();
            }
            return;
        }

        let text = match self.mode {
            Mode::Encrypt => "Chiffrer",
            Mode::Decrypt => "Déchiffrer",
        };
        let button = egui::Button::new(RichText::new(text).size(16.0));
        if ui.add_enabled(self.can_start(), button).clicked() {
            if self.mode == Mode::Encrypt && self.delete_source {
                self.confirm_delete_open = true;
            } else {
                self.start(ui.ctx());
            }
        }
    }

    fn delete_confirmation(&mut self, ctx: &egui::Context) {
        if !self.confirm_delete_open {
            return;
        }
        let mut choice = None;
        let modal = egui::Modal::new(egui::Id::unique("confirmer-suppression")).show(ctx, |ui| {
            ui.set_max_width(380.0);
            ui.heading("Supprimer le fichier d'origine ?");
            ui.label(
                "Après un chiffrement réussi, le fichier d'origine sera supprimé. \
                 Cette suppression n'est pas un effacement sécurisé : sur SSD, clé USB \
                 ou dossier synchronisé, des copies peuvent subsister.",
            );
            ui.label(RichText::new("Assurez-vous de ne pas oublier le mot de passe.").strong());
            ui.horizontal(|ui| {
                if ui.button("Chiffrer et supprimer").clicked() {
                    choice = Some(true);
                }
                if ui.button("Annuler").clicked() {
                    choice = Some(false);
                }
            });
        });
        if modal.should_close() && choice.is_none() {
            choice = Some(false);
        }
        if let Some(confirmed) = choice {
            self.confirm_delete_open = false;
            if confirmed {
                self.start(ctx);
            }
        }
    }
}

fn has_enc_extension(p: &Path) -> bool {
    p.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(fileops::EXTENSION))
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.handle_drop(&ctx);
        let progress = self.poll_job();

        egui::Panel::top("entete").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("cryptage");
                ui.add_space(16.0);
                ui.add_enabled_ui(!self.busy(), |ui| {
                    let mut mode = self.mode;
                    ui.selectable_value(
                        &mut mode,
                        Mode::Encrypt,
                        RichText::new("Chiffrer").size(15.0),
                    );
                    ui.selectable_value(
                        &mut mode,
                        Mode::Decrypt,
                        RichText::new("Déchiffrer").size(15.0),
                    );
                    self.set_mode(mode);
                });
            });
            ui.add_space(6.0);
        });

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.file_section(ui);
                self.password_section(ui);
                self.options_section(ui);
                self.action_section(ui, progress);
                match &self.status {
                    Some(Status::Success(m)) => {
                        ui.add_space(8.0);
                        ui.colored_label(OK, m.as_str());
                    }
                    Some(Status::Error(m)) => {
                        ui.add_space(8.0);
                        ui.colored_label(ERR, m.as_str());
                    }
                    None => {}
                }
            });
        });

        self.delete_confirmation(&ctx);

        if ctx.input(|i| !i.raw.hovered_files.is_empty()) && !self.busy() {
            let rect = ctx.content_rect();
            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::unique("depot"),
            ));
            painter.rect_filled(rect, 0.0, Color32::from_black_alpha(160));
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "Déposez le fichier ici",
                egui::FontId::proportional(24.0),
                Color32::WHITE,
            );
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.clear_secrets();
    }
}
