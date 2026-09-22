'use strict';

var core = require('@tauri-apps/api/core');

// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT
/**
 * Store secrets and keys using the [IOTA Stronghold](https://github.com/iotaledger/stronghold.rs)
 * encrypted database and secure runtime.
 *
 * @module
 */
/**
 * A pointer to a record inside a vault, either addressed by its record path
 * ({@link Location.generic}) or by a counter ({@link Location.counter}).
 *
 * @since 2.0.0
 */
class Location {
    /**
     * Creates a location of the given kind. Prefer the {@link Location.generic}
     * and {@link Location.counter} helpers, which fill the payload for you.
     *
     * @example
     * ```typescript
     * import { Location } from '@tauri-apps/plugin-stronghold';
     * const location = new Location('Generic', { vault: 'my-vault', record: 'my-record' });
     * ```
     *
     * @param type The location kind, either `Generic` or `Counter`.
     * @param payload The data identifying the record inside the vault.
     */
    constructor(type, payload) {
        this.type = type;
        this.payload = payload;
    }
    /**
     * Creates a location addressing a record of a vault by its record path.
     *
     * @example
     * ```typescript
     * import { Location } from '@tauri-apps/plugin-stronghold';
     * const location = Location.generic('my-vault', 'my-record');
     * ```
     *
     * @param vault The path of the vault holding the record.
     * @param record The path of the record inside the vault.
     * @returns The location of the record.
     */
    static generic(vault, record) {
        return new Location('Generic', {
            vault,
            record
        });
    }
    /**
     * Creates a location addressing a record of a vault by a counter.
     *
     * @example
     * ```typescript
     * import { Location } from '@tauri-apps/plugin-stronghold';
     * const location = Location.counter('my-vault', 0);
     * ```
     *
     * @param vault The path of the vault holding the record.
     * @param counter The counter identifying the record inside the vault.
     * @returns The location of the record.
     */
    static counter(vault, counter) {
        return new Location('Counter', {
            vault,
            counter
        });
    }
}
class ProcedureExecutor {
    constructor(procedureArgs) {
        this.procedureArgs = procedureArgs;
    }
    /**
     * Generate a SLIP10 seed for the given location.
     * @param outputLocation Location of the record where the seed will be stored.
     * @param sizeBytes The size in bytes of the SLIP10 seed.
     * @returns A promise resolving to the bytes returned by the procedure.
     */
    async generateSLIP10Seed(outputLocation, sizeBytes) {
        return await core.invoke('plugin:stronghold|execute_procedure', {
            ...this.procedureArgs,
            procedure: {
                type: 'SLIP10Generate',
                payload: {
                    output: outputLocation,
                    sizeBytes
                }
            }
        }).then((n) => Uint8Array.from(n));
    }
    /**
     * Derive a SLIP10 private key using a seed or key. The derivation is always
     * performed on the Ed25519 curve.
     * @param chain The chain path.
     * @param source The source type, either 'Seed' or 'Key'.
     * @param sourceLocation The source location, must be the `outputLocation` of a previous call to `generateSLIP10Seed` or `deriveSLIP10`.
     * @param outputLocation Location of the record where the private key will be stored.
     * @returns A promise resolving to the bytes returned by the procedure.
     */
    async deriveSLIP10(chain, source, sourceLocation, outputLocation) {
        return await core.invoke('plugin:stronghold|execute_procedure', {
            ...this.procedureArgs,
            procedure: {
                type: 'SLIP10Derive',
                payload: {
                    chain,
                    input: {
                        type: source,
                        payload: sourceLocation
                    },
                    output: outputLocation
                }
            }
        }).then((n) => Uint8Array.from(n));
    }
    /**
     * Store a BIP39 mnemonic.
     * @param mnemonic The mnemonic string.
     * @param outputLocation The location of the record where the BIP39 mnemonic will be stored.
     * @param passphrase The optional mnemonic passphrase.
     * @returns A promise resolving to the bytes returned by the procedure.
     */
    async recoverBIP39(mnemonic, outputLocation, passphrase) {
        return await core.invoke('plugin:stronghold|execute_procedure', {
            ...this.procedureArgs,
            procedure: {
                type: 'BIP39Recover',
                payload: {
                    mnemonic,
                    passphrase,
                    output: outputLocation
                }
            }
        }).then((n) => Uint8Array.from(n));
    }
    /**
     * Generate a BIP39 seed. The mnemonic is generated in English.
     * @param outputLocation The location of the record where the BIP39 seed will be stored.
     * @param passphrase The optional mnemonic passphrase.
     * @returns A promise resolving to the bytes returned by the procedure.
     */
    async generateBIP39(outputLocation, passphrase) {
        return await core.invoke('plugin:stronghold|execute_procedure', {
            ...this.procedureArgs,
            procedure: {
                type: 'BIP39Generate',
                payload: {
                    output: outputLocation,
                    passphrase
                }
            }
        }).then((n) => Uint8Array.from(n));
    }
    /**
     * Gets the Ed25519 public key of a SLIP10 private key.
     * @param privateKeyLocation The location of the private key. Must be the `outputLocation` of a previous call to `deriveSLIP10`.
     * @returns A promise resolving to the public key hex string.
     *
     * @since 2.0.0
     */
    async getEd25519PublicKey(privateKeyLocation) {
        return await core.invoke('plugin:stronghold|execute_procedure', {
            ...this.procedureArgs,
            procedure: {
                type: 'PublicKey',
                payload: {
                    type: 'Ed25519',
                    privateKey: privateKeyLocation
                }
            }
        }).then((n) => Uint8Array.from(n));
    }
    /**
     * Creates a Ed25519 signature from a private key.
     * @param privateKeyLocation The location of the record where the private key is stored. Must be the `outputLocation` of a previous call to `deriveSLIP10`.
     * @param msg The message to sign.
     * @returns A promise resolving to the signature hex string.
     *
     * @since 2.0.0
     */
    async signEd25519(privateKeyLocation, msg) {
        return await core.invoke('plugin:stronghold|execute_procedure', {
            ...this.procedureArgs,
            procedure: {
                type: 'Ed25519Sign',
                payload: {
                    privateKey: privateKeyLocation,
                    msg
                }
            }
        }).then((n) => Uint8Array.from(n));
    }
}
/**
 * A client of a stronghold snapshot, owning a set of vaults and a key-value store.
 * Clients are obtained with {@link Stronghold.loadClient} and {@link Stronghold.createClient}.
 *
 * @since 2.0.0
 */
class Client {
    /**
     * Creates a client handle for a client that was already loaded or created.
     * Prefer {@link Stronghold.loadClient} and {@link Stronghold.createClient},
     * which also register the client on the Rust side.
     *
     * @example
     * ```typescript
     * import { Client } from '@tauri-apps/plugin-stronghold';
     * const client = new Client('/path/to/snapshot.hold', 'my-client');
     * ```
     *
     * @param path The path of the snapshot file the client belongs to.
     * @param name The name identifying the client inside the snapshot.
     */
    constructor(path, name) {
        this.path = path;
        this.name = name;
    }
    /**
     * Gets a handle to the vault with the given name. The vault is created on the
     * Rust side when the first secret is written to it.
     *
     * @example
     * ```typescript
     * import { Stronghold } from '@tauri-apps/plugin-stronghold';
     * const stronghold = await Stronghold.load('/path/to/snapshot.hold', 'password');
     * const client = await stronghold.createClient('my-client');
     * const vault = client.getVault('my-vault');
     * ```
     *
     * @param name The path of the vault.
     * @returns The vault handle.
     */
    getVault(name) {
        return new Vault(this.path, this.name, name);
    }
    /**
     * Gets a handle to the key-value store of this client.
     *
     * @example
     * ```typescript
     * import { Stronghold } from '@tauri-apps/plugin-stronghold';
     * const stronghold = await Stronghold.load('/path/to/snapshot.hold', 'password');
     * const client = await stronghold.createClient('my-client');
     * const store = client.getStore();
     * ```
     *
     * @returns The store handle.
     */
    getStore() {
        return new Store(this.path, this.name);
    }
}
/**
 * The key-value store of a {@link Client}. Unlike a {@link Vault}, the values
 * stored here can be read back directly.
 *
 * @since 2.0.0
 */
class Store {
    /**
     * Creates a store handle for a client that was already loaded or created.
     * Prefer {@link Client.getStore}.
     *
     * @example
     * ```typescript
     * import { Store } from '@tauri-apps/plugin-stronghold';
     * const store = new Store('/path/to/snapshot.hold', 'my-client');
     * ```
     *
     * @param path The path of the snapshot file the store belongs to.
     * @param client The name of the client owning the store.
     */
    constructor(path, client) {
        this.path = path;
        this.client = client;
    }
    /**
     * Reads the value of a record of this store.
     *
     * @example
     * ```typescript
     * import { Stronghold } from '@tauri-apps/plugin-stronghold';
     * const stronghold = await Stronghold.load('/path/to/snapshot.hold', 'password');
     * const client = await stronghold.createClient('my-client');
     * const value = await client.getStore().get('my-key');
     * ```
     *
     * @param key The key of the record.
     * @returns A promise resolving to the stored value, or `null` if the key does not exist.
     */
    async get(key) {
        return await core.invoke('plugin:stronghold|get_store_record', {
            snapshotPath: this.path,
            client: this.client,
            key
        }).then((v) => v && Uint8Array.from(v));
    }
    /**
     * Inserts a record in this store, replacing the previous value of the key.
     * Note that the snapshot is only persisted when {@link Stronghold.save} is called.
     *
     * @example
     * ```typescript
     * import { Stronghold } from '@tauri-apps/plugin-stronghold';
     * const stronghold = await Stronghold.load('/path/to/snapshot.hold', 'password');
     * const client = await stronghold.createClient('my-client');
     * const data = Array.from(new TextEncoder().encode('Hello, World!'));
     * await client.getStore().insert('my-key', data);
     * await stronghold.save();
     * ```
     *
     * @param key The key of the record.
     * @param value The value of the record, as an array of bytes.
     * @param lifetime The optional duration after which the record expires.
     */
    async insert(key, value, lifetime) {
        await core.invoke('plugin:stronghold|save_store_record', {
            snapshotPath: this.path,
            client: this.client,
            key,
            value,
            lifetime
        });
    }
    /**
     * Deletes a record from this store.
     *
     * @example
     * ```typescript
     * import { Stronghold } from '@tauri-apps/plugin-stronghold';
     * const stronghold = await Stronghold.load('/path/to/snapshot.hold', 'password');
     * const client = await stronghold.createClient('my-client');
     * await client.getStore().remove('my-key');
     * ```
     *
     * @param key The key of the record.
     * @returns A promise resolving to the deleted value, or `null` if the key did not exist.
     */
    async remove(key) {
        return await core.invoke('plugin:stronghold|remove_store_record', {
            snapshotPath: this.path,
            client: this.client,
            key
        }).then((v) => v && Uint8Array.from(v));
    }
}
/**
 * A key-value storage that allows create, update and delete operations.
 * It does not allow reading the data, so one of the procedures must be used to manipulate
 * the stored data, allowing secure storage of secrets.
 *
 * @since 2.0.0
 */
class Vault extends ProcedureExecutor {
    /**
     * Creates a vault handle for a client that was already loaded or created.
     * Prefer {@link Client.getVault}.
     *
     * @example
     * ```typescript
     * import { Vault } from '@tauri-apps/plugin-stronghold';
     * const vault = new Vault('/path/to/snapshot.hold', 'my-client', 'my-vault');
     * ```
     *
     * @param path The path of the snapshot file the vault belongs to.
     * @param client The name of the client owning the vault.
     * @param name The path identifying the vault inside the client.
     */
    constructor(path, client, name) {
        super({
            snapshotPath: path,
            client,
            vault: name
        });
        this.path = path;
        this.client = client;
        this.name = name;
    }
    /**
     * Writes a secret to this vault. Note that the snapshot is only persisted
     * when {@link Stronghold.save} is called.
     *
     * @example
     * ```typescript
     * import { Stronghold } from '@tauri-apps/plugin-stronghold';
     * const stronghold = await Stronghold.load('/path/to/snapshot.hold', 'password');
     * const client = await stronghold.createClient('my-client');
     * const secret = Array.from(new TextEncoder().encode('secret value'));
     * await client.getVault('my-vault').insert('my-record', secret);
     * await stronghold.save();
     * ```
     *
     * @param recordPath The path of the record inside this vault.
     * @param secret The secret to store, as an array of bytes.
     */
    async insert(recordPath, secret) {
        await core.invoke('plugin:stronghold|save_secret', {
            snapshotPath: this.path,
            client: this.client,
            vault: this.name,
            recordPath,
            secret
        });
    }
    /**
     * Deletes a secret from this vault. Only the record path of the given
     * location is used, the vault is always this one.
     *
     * @example
     * ```typescript
     * import { Stronghold, Location } from '@tauri-apps/plugin-stronghold';
     * const stronghold = await Stronghold.load('/path/to/snapshot.hold', 'password');
     * const client = await stronghold.createClient('my-client');
     * await client
     *   .getVault('my-vault')
     *   .remove(Location.generic('my-vault', 'my-record'));
     * ```
     *
     * @param location The location of the record to delete.
     */
    async remove(location) {
        await core.invoke('plugin:stronghold|remove_secret', {
            snapshotPath: this.path,
            client: this.client,
            vault: this.name,
            recordPath: location.payload.record
        });
    }
}
/**
 * A representation of an access to a stronghold.
 *
 * @since 2.0.0
 */
class Stronghold {
    /**
     * Creates a handle to the stronghold initialized for the given snapshot path.
     * @param path The path of the snapshot file.
     */
    constructor(path) {
        this.path = path;
    }
    /**
     * Load the snapshot if it exists (password must match), or start a fresh stronghold instance otherwise.
     *
     * @example
     * ```typescript
     * import { Stronghold } from '@tauri-apps/plugin-stronghold';
     * import { appDataDir } from '@tauri-apps/api/path';
     * const stronghold = await Stronghold.load(`${await appDataDir()}/vault.hold`, 'password');
     * ```
     *
     * @param path The path of the snapshot file.
     * @param password The password used to encrypt and decrypt the snapshot.
     * @returns A promise resolving to the stronghold instance.
     */
    static async load(path, password) {
        return await core.invoke('plugin:stronghold|initialize', {
            snapshotPath: path,
            password
        }).then(() => new Stronghold(path));
    }
    /**
     * Saves the snapshot and removes this instance from the cache.
     *
     * @example
     * ```typescript
     * import { Stronghold } from '@tauri-apps/plugin-stronghold';
     * const stronghold = await Stronghold.load('/path/to/snapshot.hold', 'password');
     * await stronghold.unload();
     * ```
     */
    async unload() {
        await core.invoke('plugin:stronghold|destroy', {
            snapshotPath: this.path
        });
    }
    /**
     * Loads an existing client from the snapshot. The promise rejects if the
     * client does not exist in the snapshot or was already loaded.
     *
     * @example
     * ```typescript
     * import { Stronghold } from '@tauri-apps/plugin-stronghold';
     * const stronghold = await Stronghold.load('/path/to/snapshot.hold', 'password');
     * const client = await stronghold.loadClient('my-client');
     * ```
     *
     * @param client The name of the client.
     * @returns A promise resolving to the loaded client.
     */
    async loadClient(client) {
        return await core.invoke('plugin:stronghold|load_client', {
            snapshotPath: this.path,
            client
        }).then(() => new Client(this.path, client));
    }
    /**
     * Creates a new empty client on this stronghold.
     *
     * @example
     * ```typescript
     * import { Stronghold } from '@tauri-apps/plugin-stronghold';
     * const stronghold = await Stronghold.load('/path/to/snapshot.hold', 'password');
     * let client;
     * try {
     *   client = await stronghold.loadClient('my-client');
     * } catch {
     *   client = await stronghold.createClient('my-client');
     * }
     * ```
     *
     * @param client The name of the client.
     * @returns A promise resolving to the created client.
     */
    async createClient(client) {
        return await core.invoke('plugin:stronghold|create_client', {
            snapshotPath: this.path,
            client
        }).then(() => new Client(this.path, client));
    }
    /**
     * Persists the stronghold state to the snapshot.
     *
     * @example
     * ```typescript
     * import { Stronghold } from '@tauri-apps/plugin-stronghold';
     * const stronghold = await Stronghold.load('/path/to/snapshot.hold', 'password');
     * const client = await stronghold.createClient('my-client');
     * await client.getStore().insert('my-key', [1, 2, 3]);
     * await stronghold.save();
     * ```
     */
    async save() {
        await core.invoke('plugin:stronghold|save', {
            snapshotPath: this.path
        });
    }
}

exports.Client = Client;
exports.Location = Location;
exports.Store = Store;
exports.Stronghold = Stronghold;
exports.Vault = Vault;
