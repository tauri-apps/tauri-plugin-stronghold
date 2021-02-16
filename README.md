# Tauri Plugin Stronghold
This plugin provides a "classical" Tauri Plugin Interface to the [IOTA Stronghold](https://github.com/iotaledger/stronghold.rs) encrypted database, secure runtime, and peer-to-peer service.

## Note:
This plugin is currently written to comply with the pre-beta version of Tauri. It will change when the beta release candidate is published.

## Architecture
This repo might appear to be strange, but it is really just a hybrid Rust / Typescript project that recommends a specific type of consumption, namely using GIT as the secure distribution mechanism, and referencing specific unforgeable git tags.

There is one entry point for both Rust and JS components of this plugin: 


## Installation
There are three general methods of installation that we can recommend.
1. Pull sources directly from Github using git tags (preferred, most flexible for you, shown below)
2. Git submodule install this repo in your tauri project and then use `file` protocol to ingest the source
3. Use crates.io and npm (easiest, supply chain risk, requires you to trust that our publishing pipeline worked)

For more details and usage see [the svelte demo](examples/svelte-app/src/App.svelte). Please note, below in the dependencies you can also lock to a revision/tag in both the `Cargo.toml` and `package.json`

### RUST
`src-tauri/Cargo.toml`
```yaml
[dependencies.tauri-plugin-stronghold]
git = "https://github.com/tauri-apps/tauri-plugin-stronghold"
tag = "v0.1.0"
#branch = "main"
```

Use in `src-tauri/src/main.rs`:
```rust
use tauri_plugin_stronghold::TauriStronghold;

fn main() {
    tauri::AppBuilder::new()
        .plugin(TauriStronghold {})
        .build()
        .run();
}
```

### WEBVIEW
`Install`
```
npm install github:tauri-apps/tauri-plugin-stronghold-api#v0.1.0
# or
yarn add github:tauri-apps/tauri-plugin-stronghold-api#v0.1.0
```

`package.json`
```json
  "dependencies": {
    "tauri-plugin-stronghold-api": "tauri-apps/tauri-plugin-stronghold-api#v0.1.0",
```

Use within your JS/TS:
```
import { Stronghold, Location } from 'tauri-plugin-stronghold-api'
```

# License
MIT / Apache-2.0
