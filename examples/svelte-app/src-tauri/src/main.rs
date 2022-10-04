#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

fn main() {
  tauri::Builder::default()
    .plugin(
      tauri_plugin_stronghold::Builder::new(|password| {
        let config = argon2::Config {
          lanes: 2,
          mem_cost: 50_000,
          time_cost: 30,
          thread_mode: argon2::ThreadMode::from_threads(2),
          variant: argon2::Variant::Argon2id,
          ..Default::default()
        };

        let key = argon2::hash_raw(password.as_ref(), b"SALT_IDEALLY_SHOULD_BE_RANDOM", &config)
          .expect("failed to hash password");

        key.to_vec()
      })
      .build(),
    )
    .run(tauri::generate_context!())
    .expect("failed to run app");
}
