#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use tauri_stronghold::TauriStronghold;

fn main() {
    tauri::AppBuilder::new()
        .plugin(TauriStronghold {})
        .build()
        .run();
}
