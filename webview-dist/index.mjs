import { invoke } from '@tauri-apps/api/tauri';

function toBytesDto(v) {
    if (typeof v === 'string') {
        return v;
    }
    return Array.from(v instanceof ArrayBuffer
        ? new Uint8Array(v)
        : v);
}
class Location {
    constructor(type, payload) {
        this.type = type;
        this.payload = payload;
    }
    static generic(vault, record) {
        return new Location('Generic', {
            vault: toBytesDto(vault),
            record: toBytesDto(record)
        });
    }
    static counter(vault, counter) {
        return new Location('Counter', {
            vault: toBytesDto(vault),
            counter
        });
    }
}
class ProcedureExecutor {
    constructor(procedureArgs) {
        this.procedureArgs = procedureArgs;
    }
    generateSLIP10Seed(outputLocation, sizeBytes) {
        return invoke(`plugin:stronghold|execute_procedure`, {
            ...this.procedureArgs,
            procedure: {
                type: 'SLIP10Generate',
                payload: {
                    output: outputLocation,
                    sizeBytes,
                }
            }
        }).then(n => Uint8Array.from(n));
    }
    deriveSLIP10(chain, source, sourceLocation, outputLocation) {
        return invoke(`plugin:stronghold|execute_procedure`, {
            ...this.procedureArgs,
            procedure: {
                type: 'SLIP10Derive',
                payload: {
                    chain,
                    input: {
                        type: source,
                        payload: sourceLocation
                    },
                    output: outputLocation,
                }
            }
        }).then(n => Uint8Array.from(n));
    }
    recoverBIP39(mnemonic, outputLocation, passphrase) {
        return invoke(`plugin:stronghold|execute_procedure`, {
            ...this.procedureArgs,
            procedure: {
                type: 'BIP39Recover',
                payload: {
                    mnemonic,
                    passphrase,
                    output: outputLocation,
                }
            }
        }).then(n => Uint8Array.from(n));
    }
    generateBIP39(outputLocation, passphrase) {
        return invoke(`plugin:stronghold|execute_procedure`, {
            ...this.procedureArgs,
            procedure: {
                type: 'BIP39Generate',
                payload: {
                    output: outputLocation,
                    passphrase,
                }
            }
        }).then(n => Uint8Array.from(n));
    }
    getEd25519PublicKey(privateKeyLocation) {
        return invoke(`plugin:stronghold|execute_procedure`, {
            ...this.procedureArgs,
            procedure: {
                type: 'PublicKey',
                payload: {
                    type: 'Ed25519',
                    privateKey: privateKeyLocation
                }
            }
        }).then(n => Uint8Array.from(n));
    }
    signEd25519(privateKeyLocation, msg) {
        return invoke(`plugin:stronghold|execute_procedure`, {
            ...this.procedureArgs,
            procedure: {
                type: 'Ed25519Sign',
                payload: {
                    privateKey: privateKeyLocation,
                    msg
                }
            }
        }).then(n => Uint8Array.from(n));
    }
}
class Client {
    constructor(path, name) {
        this.path = path;
        this.name = toBytesDto(name);
    }
    getVault(name) {
        return new Vault(this.path, this.name, toBytesDto(name));
    }
    getStore() {
        return new Store(this.path, this.name);
    }
}
class Store {
    constructor(path, client) {
        this.path = path;
        this.client = client;
    }
    get(key) {
        return invoke('plugin:stronghold|get_store_record', {
            snapshotPath: this.path,
            client: this.client,
            key: toBytesDto(key)
        }).then(v => Uint8Array.from(v));
    }
    insert(key, value, lifetime) {
        return invoke('plugin:stronghold|save_store_record', {
            snapshotPath: this.path,
            client: this.client,
            key: toBytesDto(key),
            value,
            lifetime
        });
    }
    remove(key) {
        return invoke('plugin:stronghold|remove_store_record', {
            snapshotPath: this.path,
            client: this.client,
            key: toBytesDto(key)
        }).then(v => v ? Uint8Array.from(v) : null);
    }
}
class Vault extends ProcedureExecutor {
    constructor(path, client, name) {
        super({
            snapshotPath: path,
            client,
            vault: name,
        });
        this.path = path;
        this.client = toBytesDto(client);
        this.name = toBytesDto(name);
    }
    insert(recordPath, secret) {
        return invoke('plugin:stronghold|save_secret', {
            snapshotPath: this.path,
            client: this.client,
            vault: this.name,
            recordPath: toBytesDto(recordPath),
            secret,
        });
    }
    remove(location) {
        return invoke('plugin:stronghold|remove_secret', {
            snapshotPath: this.path,
            client: this.client,
            vault: this.name,
            location,
        });
    }
}
class Communication {
    constructor(path) {
        this.path = path;
    }
    connect(peer) {
        return invoke('plugin:stronghold|p2p_connect', {
            snapshotPath: this.path,
            peer
        });
    }
    serve() {
        return invoke('plugin:stronghold|p2p_serve', {
            snapshotPath: this.path
        });
    }
    send(peer, client, request) {
        return invoke('plugin:stronghold|p2p_send', {
            snapshotPath: this.path,
            peer,
            client: toBytesDto(client),
            request,
        });
    }
    getSnapshotHierarchy(peer, client) {
        return this.send(peer, client, {
            type: 'SnapshotRequest',
            payload: {
                request: {
                    type: 'GetRemoteHierarchy'
                }
            }
        });
    }
    checkVault(peer, client, vault) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'CheckVault',
                    payload: {
                        vaultPath: vault
                    }
                }
            }
        });
    }
    checkRecord(peer, client, location) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'CheckRecord',
                    payload: {
                        location
                    }
                }
            }
        });
    }
    writeToVault(peer, client, location, payload) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'WriteToVault',
                    payload: {
                        location,
                        payload
                    }
                }
            }
        });
    }
    revokeData(peer, client, location) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'RevokeData',
                    payload: {
                        location,
                    }
                }
            }
        });
    }
    deleteData(peer, client, location) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'DeleteData',
                    payload: {
                        location,
                    }
                }
            }
        });
    }
    readFromStore(peer, client, key) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'ReadFromStore',
                    payload: {
                        key: toBytesDto(key),
                    }
                }
            }
        });
    }
    writeToStore(peer, client, key, payload, lifetime) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'WriteToStore',
                    payload: {
                        key: toBytesDto(key),
                        payload,
                        lifetime
                    }
                }
            }
        });
    }
    deleteFromStore(peer, client, key) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'DeleteFromStore',
                    payload: {
                        key: toBytesDto(key),
                    }
                }
            }
        });
    }
    generateSLIP10Seed(peer, client, outputLocation, sizeBytes) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'Procedures',
                    payload: {
                        procedures: [{
                                type: 'SLIP10Generate',
                                payload: {
                                    output: outputLocation,
                                    sizeBytes,
                                }
                            }],
                    }
                }
            }
        }).then(n => Uint8Array.from(n));
    }
    deriveSLIP10(peer, client, chain, source, sourceLocation, outputLocation) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'Procedures',
                    payload: {
                        procedures: [{
                                type: 'SLIP10Derive',
                                payload: {
                                    chain,
                                    input: {
                                        type: source,
                                        payload: sourceLocation
                                    },
                                    output: outputLocation,
                                }
                            }],
                    }
                }
            }
        }).then(n => Uint8Array.from(n));
    }
    recoverBIP39(peer, client, mnemonic, outputLocation, passphrase) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'Procedures',
                    payload: {
                        procedures: [{
                                type: 'BIP39Recover',
                                payload: {
                                    mnemonic,
                                    passphrase,
                                    output: outputLocation,
                                }
                            }],
                    }
                }
            }
        }).then(n => Uint8Array.from(n));
    }
    generateBIP39(peer, client, outputLocation, passphrase) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'Procedures',
                    payload: {
                        procedures: [{
                                type: 'BIP39Generate',
                                payload: {
                                    output: outputLocation,
                                    passphrase,
                                }
                            }],
                    }
                }
            }
        }).then(n => Uint8Array.from(n));
    }
    getEd25519PublicKey(peer, client, privateKeyLocation) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'Procedures',
                    payload: {
                        procedures: [{
                                type: 'PublicKey',
                                payload: {
                                    type: 'Ed25519',
                                    privateKey: privateKeyLocation
                                }
                            }],
                    }
                }
            }
        }).then(n => Uint8Array.from(n));
    }
    signEd25519(peer, client, privateKeyLocation, msg) {
        return this.send(peer, client, {
            type: 'ClientRequest',
            payload: {
                request: {
                    type: 'Procedures',
                    payload: {
                        procedures: [{
                                type: 'Ed25519Sign',
                                payload: {
                                    privateKey: privateKeyLocation,
                                    msg
                                }
                            }],
                    }
                }
            }
        }).then(n => Uint8Array.from(n));
    }
    stop() {
        return invoke('plugin:stronghold|p2p_stop', {
            snapshotPath: this.path
        });
    }
    startListening(addr) {
        return invoke('plugin:stronghold|p2p_start_listening', {
            snapshotPath: this.path,
            addr
        });
    }
    stopListening() {
        return invoke('plugin:stronghold|p2p_stop_listening', {
            snapshotPath: this.path,
        });
    }
    addPeerAddr(peerId, addr) {
        return invoke('plugin:stronghold|p2p_add_peer', {
            snapshotPath: this.path,
            peerId,
            addr
        });
    }
}
class Stronghold {
    constructor(path, password) {
        this.path = path;
        this.reload(password);
    }
    reload(password) {
        return invoke('plugin:stronghold|initialize', {
            snapshotPath: this.path,
            password
        });
    }
    unload() {
        return invoke('plugin:stronghold|destroy', {
            snapshotPath: this.path
        });
    }
    loadClient(client) {
        return invoke('plugin:stronghold|load_client', {
            snapshotPath: this.path,
            client: toBytesDto(client)
        }).then(() => new Client(this.path, client));
    }
    createClient(client) {
        return invoke('plugin:stronghold|create_client', {
            snapshotPath: this.path,
            client: toBytesDto(client)
        }).then(() => new Client(this.path, client));
    }
    save() {
        return invoke('plugin:stronghold|save', {
            snapshotPath: this.path
        });
    }
    spawnCommunication(client, config, keypair) {
        return invoke('plugin:stronghold|p2p_spawn', {
            snapshotPath: this.path,
            client: toBytesDto(client),
            config,
            keypair
        }).then(() => new Communication(this.path));
    }
}

export { Client, Communication, Location, Store, Stronghold, Vault };
