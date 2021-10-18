# Tauri Plugin Stronghold
![Test](https://github.com/tauri-apps/tauri-plugin-stronghold/workflows/Test/badge.svg)

This plugin provides a "classical" Tauri Plugin Interface to the [IOTA Stronghold](https://github.com/iotaledger/stronghold.rs) encrypted database, secure runtime, and peer-to-peer service.

## Architecture
This repo shape might appear to be strange, but it is really just a hybrid Rust / Typescript project that recommends a specific type of consumption, namely using GIT as the secure distribution mechanism, and referencing specific unforgeable git hashes. Of course, it can also be consumed via Cargo and NPM.

### `/src`
Rust source code that contains the plugin definition and Stronghold features.

### `/webview-src`
Typescript source for the /dist folder that provides an API to interface with the rust code.

### `/webview-dist`
Tree-shakeable transpiled JS to be consumed in a WRY webview.

### `/bindings`
Forthcoming tauri bindings to other programming languages, like DENO.

## Installation
There are three general methods of installation that we can recommend.
1. Pull sources directly from Github using git tags / revision hashes (most secure, good for developement, shown below)
2. Git submodule install this repo in your tauri project and then use `file` protocol to ingest the source
3. Use crates.io and npm (easiest, and requires you to trust that our publishing pipeline worked)

For more details and usage see [the svelte demo](examples/svelte-app/src/App.svelte). Please note, below in the dependencies you can also lock to a revision/tag in both the `Cargo.toml` and `package.json`

### RUST
`src-tauri/Cargo.toml`
```yaml
[dependencies.tauri-plugin-stronghold]
git = "https://github.com/tauri-apps/tauri-plugin-stronghold"
tag = "v0.1.0"
#branch = "main"

# temporary fix to version resolution
[patch.crates-io]
aesni = { git = "https://github.com/RustCrypto/block-ciphers/", rev = "268dadc93df08928de3bc510ddf20aabfcc49435" }
aes-soft = { git = "https://github.com/RustCrypto/block-ciphers/", rev = "268dadc93df08928de3bc510ddf20aabfcc49435" }
```

Use in `src-tauri/src/main.rs`:
```rust
use tauri_plugin_stronghold::TauriStronghold;

fn main() {
    tauri::Builder::default()
        .plugin(TauriStronghold {})
        .build()
        .run();
}
```

### WEBVIEW
`Install from a tagged release`
```
npm install github:tauri-apps/tauri-plugin-stronghold#v0.2.0
# or
yarn add github:tauri-apps/tauri-plugin-stronghold#v0.2.0
```

`Install from a commit`
```
npm install github:tauri-apps/tauri-plugin-stronghold#6749525a47a95439c9703d3a49b94ac65660998f
# or
yarn add github:tauri-apps/tauri-plugin-stronghold#6749525a47a95439c9703d3a49b94ac65660998f
```

`package.json`
```json
  "dependencies": {
    "tauri-plugin-stronghold-api": "github:tauri-apps/tauri-plugin-stronghold#v0.2.0",
```

Use within your JS/TS:
```ts
import { Stronghold, Location } from 'tauri-plugin-stronghold-api'
```

# License
MIT / Apache-2.0
