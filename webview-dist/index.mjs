import { invoke } from '@tauri-apps/api/tauri';

class Location {
    constructor(type, payload) {
        this.type = type;
        this.payload = payload;
    }
    static generic(vaultName, recordName) {
        return new Location('Generic', {
            vault: vaultName,
            record: recordName
        });
    }
    static counter(vaultName, counter) {
        return new Location('Counter', {
            vault: vaultName,
            counter
        });
    }
}
function setPasswordClearInterval(interval) {
    return invoke('plugin:stronghold|set_password_clear_interval', {
        interval
    });
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
        });
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
        });
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
        });
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
        });
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
        });
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
        });
    }
}
class Client {
    constructor(path, name) {
        this.path = path;
        this.name = name;
    }
    getVault(name) {
        return new Vault(this.path, this.name, name);
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
            key
        });
    }
    insert(key, value, lifetime) {
        return invoke('plugin:stronghold|save_store_record', {
            snapshotPath: this.path,
            client: this.client,
            key,
            value,
            lifetime
        });
    }
    remove(key) {
        return invoke('plugin:stronghold|remove_store_record', {
            snapshotPath: this.path,
            client: this.client,
            key
        });
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
        this.client = client;
        this.name = name;
    }
    insert(key, secret) {
        return invoke('plugin:stronghold|save_secret', {
            snapshotPath: this.path,
            client: this.client,
            vault: this.name,
            recordPath: key,
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
            client,
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
                        key,
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
                        key,
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
                        key,
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
        });
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
        });
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
        });
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
        });
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
        });
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
        });
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
            client
        }).then(() => new Client(this.path, client));
    }
    createClient(client) {
        return invoke('plugin:stronghold|create_client', {
            snapshotPath: this.path,
            client
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
            client,
            config,
            keypair
        }).then(() => new Communication(this.path));
    }
}

export { Client, Communication, Location, Store, Stronghold, Vault, setPasswordClearInterval };
