// Pas de console sous Windows en version release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod gui;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("cryptage")
            .with_inner_size([560.0, 660.0])
            .with_min_inner_size([420.0, 480.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "cryptage",
        options,
        Box::new(|_cc| Ok(Box::new(gui::App::default()))),
    )
}
