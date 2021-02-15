# Tauri Plugin Stronghold

This plugin provides a "classical" Tauri Plugin Interface to the [IOTA Stronghold](https://github.com/iotaledger/stronghold.rs) encrypted database, secure runtime, and peer-to-peer service.

## Architecture
This repo might appear to be strange, but it is really just a hybrid Rust / Typescript project that recommends a specific type of consumption, namely using GIT as the only distribution mechanism.

## Installation
For more details and usage see [the svelte demo](examples/svelte-app/src/App.svelte). Please note, below in the dependencies you can also lock to a revision/tag in both the `Cargo.toml` and `package.json`

### RUST
`src-tauri/Cargo.toml`
```yaml
[dependencies.tauri-stronghold]
git = "https://github.com/tauri-apps/tauri-plugin-stronghold.rs"
branch = "main"
```

Use in `src-tauri/src/main.rs`:
```rust
use tauri_stronghold::TauriStronghold;

fn main() {
    tauri::AppBuilder::new()
        .plugin(TauriStronghold {})
        .build()
        .run();
}
```

### WEB
`package.json`
```json
  "dependencies": {
    "tauri-stronghold-plugin-api": "tauri-apps/tauri-plugin-stronghold.rs#main",
```

Import in your JS/TS:
```
import { Stronghold, Location } from 'tauri-stronghold-plugin-api'
```


# License
MIT / Apache-2.0
