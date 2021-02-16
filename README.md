# Tauri Plugin Stronghold

This plugin provides a "classical" Tauri Plugin Interface to the [IOTA Stronghold](https://github.com/iotaledger/stronghold.rs) encrypted database, secure runtime, and peer-to-peer service.

## Architecture
This repo might appear to be strange, but it is really just a hybrid Rust / Typescript project that recommends a specific type of consumption, namely using GIT as the secure distribution mechanism, and referencing specific unforgeable git tags.

## Installation
For more details and usage see [the svelte demo](examples/svelte-app/src/App.svelte). Please note, below in the dependencies you can also lock to a revision/tag in both the `Cargo.toml` and `package.json`

### RUST
`src-tauri/Cargo.toml`
```yaml
[dependencies.tauri-stronghold]
git = "https://github.com/tauri-apps/tauri-plugin-stronghold"
tag = "v0.1.0"
#branch = "main"
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

### WEBVIEW
For security sake, we recommend using Pure GIT Tags instead of installing from NPM.

`Install`
```
npm install github:tauri-apps/tauri-plugin-stronghold#v0.1.0
# or
yarn add github:tauri-apps/tauri-plugin-stronghold#v0.1.0
```

`package.json`
```json
  "dependencies": {
    "tauri-plugin-stronghold-api": "tauri-apps/tauri-plugin-stronghold#v0.1.0",
```

Use within your JS/TS:
```
import { Stronghold, Location } from 'tauri-plugin-stronghold-api'
```

# License
MIT / Apache-2.0
