import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';

/** Relay direction. */
var RelayDirection;
(function (RelayDirection) {
    RelayDirection[RelayDirection["Dialing"] = 0] = "Dialing";
    RelayDirection[RelayDirection["Listening"] = 1] = "Listening";
    RelayDirection[RelayDirection["Both"] = 2] = "Both";
})(RelayDirection || (RelayDirection = {}));
/** Permissions that can be set for P2P access of a stronghold. */
var RequestPermission;
(function (RequestPermission) {
    /** Allow checking if a vault exists. */
    RequestPermission[RequestPermission["CheckVault"] = 0] = "CheckVault";
    /** Allow checking if a record exists. */
    RequestPermission[RequestPermission["CheckRecord"] = 1] = "CheckRecord";
    /** Allow writing to the store. */
    RequestPermission[RequestPermission["WriteToStore"] = 2] = "WriteToStore";
    /** Allow reading the store. */
    RequestPermission[RequestPermission["ReadFromStore"] = 3] = "ReadFromStore";
    /** Allow deleting store records. */
    RequestPermission[RequestPermission["DeleteFromStore"] = 4] = "DeleteFromStore";
    /** Allow creating new vaults. */
    RequestPermission[RequestPermission["CreateNewVault"] = 5] = "CreateNewVault";
    /** Allow writing to a vault. */
    RequestPermission[RequestPermission["WriteToVault"] = 6] = "WriteToVault";
    /** Allow deleting vault records. */
    RequestPermission[RequestPermission["RevokeData"] = 7] = "RevokeData";
    /** Allow garbage collecting the stronghold. */
    RequestPermission[RequestPermission["GarbageCollect"] = 8] = "GarbageCollect";
    /** Allow listing vault ids. */
    RequestPermission[RequestPermission["ListIds"] = 9] = "ListIds";
    /** Allow reading data from a snapshot. */
    RequestPermission[RequestPermission["ReadSnapshot"] = 10] = "ReadSnapshot";
    /** Allow writing to a snapshot. */
    RequestPermission[RequestPermission["WriteSnapshot"] = 11] = "WriteSnapshot";
    /** Allow writing a client to the snapshot. */
    RequestPermission[RequestPermission["FillSnapshot"] = 12] = "FillSnapshot";
    /** Allow clearing the snapshot cache. */
    RequestPermission[RequestPermission["ClearCache"] = 13] = "ClearCache";
    /** Allow running procedures. */
    RequestPermission[RequestPermission["ControlRequest"] = 14] = "ControlRequest";
})(RequestPermission || (RequestPermission = {}));
const statusChangeListeners = {};
listen('stronghold://status-change', event => {
    const { snapshotPath, status } = event.payload;
    for (const listener of (statusChangeListeners[snapshotPath] || [])) {
        listener.cb(status);
    }
});
var StrongholdFlag;
(function (StrongholdFlag) {
})(StrongholdFlag || (StrongholdFlag = {}));
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
/**
 * Sets the interval used to clear the password cache.
 * The cache is cleared after `interval` if the stronghold is not accessed.
 * @param interval
 * @returns
 */
function setPasswordClearInterval(interval) {
    return invoke('plugin:stronghold|set_password_clear_interval', {
        interval
    });
}
class ProcedureExecutor {
    constructor(isRemote, procedureArgs) {
        this.procedureArgs = procedureArgs;
        this.command = isRemote ? 'execute_remote_procedure' : 'execute_procedure';
    }
    /**
     * Generate a SLIP10 seed on the given location.
     * @param outputLocation Location of the record where the seed will be stored.
     * @param sizeBytes The size in bytes of the SLIP10 seed.
     * @param hint The record hint.
     * @returns
     */
    generateSLIP10Seed(outputLocation, sizeBytes, hint) {
        return invoke(`plugin:stronghold|${this.command}`, {
            ...this.procedureArgs,
            procedure: {
                type: 'SLIP10Generate',
                payload: {
                    output: outputLocation,
                    sizeBytes,
                    hint
                }
            }
        });
    }
    /**
     * Derive a SLIP10 private key using a seed or key.
     * @param chain The chain path.
     * @param source The source type, either 'Seed' or 'Key'.
     * @param sourceLocation The source location, must be the `outputLocation` of a previous call to `generateSLIP10Seed` or `deriveSLIP10`.
     * @param outputLocation Location of the record where the private key will be stored.
     * @param hint The record hint.
     * @returns
     */
    deriveSLIP10(chain, source, sourceLocation, outputLocation, hint) {
        return invoke(`plugin:stronghold|${this.command}`, {
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
                    hint
                }
            }
        });
    }
    /**
     * Store a BIP39 mnemonic.
     * @param mnemonic The mnemonic string.
     * @param outputLocation The location of the record where the BIP39 mnemonic will be stored.
     * @param passphrase The optional mnemonic passphrase.
     * @param hint The record hint.
     * @returns
     */
    recoverBIP39(mnemonic, outputLocation, passphrase, hint) {
        return invoke(`plugin:stronghold|${this.command}`, {
            ...this.procedureArgs,
            procedure: {
                type: 'BIP39Recover',
                payload: {
                    mnemonic,
                    passphrase,
                    output: outputLocation,
                    hint
                }
            }
        });
    }
    /**
     * Generate a BIP39 seed.
     * @param outputLocation The location of the record where the BIP39 seed will be stored.
     * @param passphrase The optional mnemonic passphrase.
     * @param hint The record hint.
     * @returns
     */
    generateBIP39(outputLocation, passphrase, hint) {
        return invoke(`plugin:stronghold|${this.command}`, {
            ...this.procedureArgs,
            procedure: {
                type: 'BIP39Generate',
                payload: {
                    output: outputLocation,
                    passphrase,
                    hint
                }
            }
        });
    }
    /**
     * Gets the Ed25519 public key of a SLIP10 private key.
     * @param privateKeyLocation The location of the private key. Must be the `outputLocation` of a previous call to `deriveSLIP10`.
     * @returns A promise resolving to the public key hex string.
     */
    getPublicKey(privateKeyLocation) {
        return invoke(`plugin:stronghold|${this.command}`, {
            ...this.procedureArgs,
            procedure: {
                type: 'Ed25519PublicKey',
                payload: {
                    privateKey: privateKeyLocation
                }
            }
        });
    }
    /**
     * Creates a Ed25519 signature from a private key.
     * @param privateKeyLocation The location of the record where the private key is stored. Must be the `outputLocation` of a previous call to `deriveSLIP10`.
     * @param msg The message to sign.
     * @returns A promise resolving to the signature hex string.
     */
    sign(privateKeyLocation, msg) {
        return invoke(`plugin:stronghold|${this.command}`, {
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
/**
 * A stronghold store that is accessed remotely via a P2P connection.
 */
class RemoteStore {
    /** @ignore */
    constructor(path, peerId) {
        this.path = path;
        this.peerId = peerId;
    }
    /**
     * Read the remote store with the given location key.
     * @param location The record location.
     * @returns
     */
    get(location) {
        return invoke('plugin:stronghold|get_remote_store_record', {
            snapshotPath: this.path,
            peerId: this.peerId,
            location
        });
    }
    /**
     * Insert the key-value pair to the remote store.
     * @param location The record location.
     * @param record The data to store on the record.
     * @param lifetime The amount of time the record must live.
     * @returns
     */
    insert(location, record, lifetime) {
        return invoke('plugin:stronghold|save_remote_store_record', {
            snapshotPath: this.path,
            peerId: this.peerId,
            location,
            record,
            lifetime
        });
    }
}
/**
 * A stronghold vault that is accessed remotely via a P2P connection.
 */
class RemoteVault extends ProcedureExecutor {
    /** @ignore */
    constructor(path, peerId) {
        super(true, {
            peerId
        });
        this.path = path;
        this.peerId = peerId;
    }
}
/**
 * A key-value storage that allows create, read, update and delete operations.
 */
class Store {
    /** @ignore */
    constructor(path, name, flags) {
        this.path = path;
        this.name = name;
        this.flags = flags;
    }
    /** @ignore */
    get store() {
        return {
            name: this.name,
            flags: this.flags
        };
    }
    /**
     * Read a record on the store.
     * @param location The record location.
     * @returns
     */
    get(location) {
        return invoke('plugin:stronghold|get_store_record', {
            snapshotPath: this.path,
            store: this.store,
            location
        });
    }
    /**
     * Save a record on the store.
     * @param location The record location.
     * @param record The data to store on the record.
     * @param lifetime The record lifetime.
     * @returns
     */
    insert(location, record, lifetime) {
        return invoke('plugin:stronghold|save_store_record', {
            snapshotPath: this.path,
            store: this.store,
            location,
            record,
            lifetime
        });
    }
    /**
     * Deletes a record.
     * @param location The record location.
     * @returns
     */
    remove(location) {
        return invoke('plugin:stronghold|remove_store_record', {
            snapshotPath: this.path,
            store: this.store,
            location
        });
    }
}
/**
 * A key-value storage that allows create, update and delete operations.
 * It does not allow reading the data, so one of the procedures must be used to manipulate
 * the stored data, allowing secure storage of secrets.
 */
class Vault extends ProcedureExecutor {
    /** @ignore */
    constructor(path, name, flags) {
        super(false, {
            snapshotPath: path,
            vault: {
                name,
                flags
            }
        });
        this.path = path;
        this.name = name;
        this.flags = flags;
    }
    /** @ignore */
    get vault() {
        return {
            name: this.name,
            flags: this.flags
        };
    }
    /**
     * Insert a record to this vault.
     * @param location The record location.
     * @param record  The record data.
     * @param recordHint The record hint.
     * @returns
     */
    insert(location, record, recordHint) {
        return invoke('plugin:stronghold|save_record', {
            snapshotPath: this.path,
            vault: this.vault,
            location,
            record,
            recordHint,
            flags: []
        });
    }
    /**
     * Remove a record from the vault.
     * @param location The record location.
     * @param gc Whether to additionally perform the gargage collection or not.
     * @returns
     */
    remove(location, gc = true) {
        return invoke('plugin:stronghold|remove_record', {
            snapshotPath: this.path,
            vault: this.vault,
            location,
            gc
        });
    }
}
/**
 * Representation of a P2P connection with a remote stronghold.
 */
class Communication {
    /** @ignore */
    constructor(path) {
        this.path = path;
    }
    /**
     * Stop the connection.
     */
    stop() {
        return invoke('plugin:stronghold|stop_communication', {
            snapshotPath: this.path
        });
    }
    /**
     * Start listening on the given address.
     * @param addr The address to connect to.
     * @returns
     */
    startListening(addr) {
        return invoke('plugin:stronghold|start_listening', {
            snapshotPath: this.path,
            addr
        });
    }
    /**
     * Gets the swarm information of the local peer.
     * @returns The swarm information.
     */
    getSwarmInfo() {
        return invoke('plugin:stronghold|get_swarm_info', { snapshotPath: this.path });
    }
    /**
     * Adds a peer.
     * @param peerId
     * @param addr
     * @param relayDirection
     * @returns
     */
    addPeer(peerId, addr, relayDirection) {
        return invoke('plugin:stronghold|add_peer', {
            snapshotPath: this.path,
            peerId,
            addr,
            relayDirection: relayDirection ? { type: RelayDirection[relayDirection] } : null
        });
    }
    /**
     * Change the relay direction of the given peer.
     * @param peerId
     * @param relayDirection
     * @returns
     */
    changeRelayDirection(peerId, relayDirection) {
        return invoke('plugin:stronghold|change_relay_direction', {
            snapshotPath: this.path,
            peerId,
            relayDirection: { type: RelayDirection[relayDirection] }
        });
    }
    /**
     * Remove the relay on the given peer.
     * @param peerId
     * @returns
     */
    removeRelay(peerId) {
        return invoke('plugin:stronghold|remove_relay', {
            snapshotPath: this.path,
            peerId
        });
    }
    /**
     * Allow all requests from the given peer list.
     * @param peers
     * @param setDefault
     * @returns
     */
    allowAllRequests(peers, setDefault = false) {
        return invoke('plugin:stronghold|allow_all_requests', {
            snapshotPath: this.path,
            peers,
            setDefault
        });
    }
    /**
     * Reject all requests from the given peer list.
     * @param peers
     * @param setDefault
     * @returns
     */
    rejectAllRequests(peers, setDefault = false) {
        return invoke('plugin:stronghold|reject_all_requests', {
            snapshotPath: this.path,
            peers,
            setDefault
        });
    }
    /**
     * Allow the specified set of requests from the given peer list.
     * @param peers
     * @param permissions
     * @param changeDefault
     * @returns
     */
    allowRequests(peers, permissions, changeDefault = false) {
        return invoke('plugin:stronghold|allow_requests', {
            snapshotPath: this.path,
            peers,
            requests: permissions.map(p => ({ type: RequestPermission[p] })),
            changeDefault
        });
    }
    /**
     * Reject the specified set of requests from the given peer list.
     * @param peers
     * @param permissions
     * @param changeDefault
     * @returns
     */
    rejectRequests(peers, permissions, changeDefault = false) {
        return invoke('plugin:stronghold|reject_requests', {
            snapshotPath: this.path,
            peers,
            requests: permissions.map(p => ({ type: RequestPermission[p] })),
            changeDefault
        });
    }
    /**
     * Remove firewall rules for the given peer list.
     * @param peers
     * @returns
     */
    removeFirewallRules(peers) {
        return invoke('plugin:stronghold|remove_firewall_rules', {
            snapshotPath: this.path,
            peers
        });
    }
    /**
     * Get a RemoteVault to interact with the given peer.
     * @param peerId
     * @returns
     */
    getRemoteVault(peerId) {
        return new RemoteVault(this.path, peerId);
    }
    /**
     * Get a RemoteStore to interact with the given peer.
     * @param peerId
     * @returns
     */
    getRemoteStore(peerId) {
        return new RemoteStore(this.path, peerId);
    }
}
/**
 * A representation of an access to a stronghold.
 */
class Stronghold {
    /**
     * Initializes a stronghold.
     * If the snapshot path located at `path` exists, the password must match.
     * @param path
     * @param password
     */
    constructor(path, password) {
        this.path = path;
        this.reload(password);
    }
    /**
     * Force a reload of the snapshot. The password must match.
     * @param password
     * @returns
     */
    reload(password) {
        return invoke('plugin:stronghold|init', {
            snapshotPath: this.path,
            password
        });
    }
    /**
     * Remove this instance from the cache.
    */
    unload() {
        return invoke('plugin:stronghold|destroy', {
            snapshotPath: this.path
        });
    }
    /**
     * Get a vault by name.
     * @param name
     * @param flags
     * @returns
     */
    getVault(name, flags) {
        return new Vault(this.path, name, flags);
    }
    /**
     * Get a store by name.
     * @param name
     * @param flags
     * @returns
     */
    getStore(name, flags) {
        return new Store(this.path, name, flags);
    }
    /**
     * Persists the stronghold state to the snapshot.
     * @returns
     */
    save() {
        return invoke('plugin:stronghold|save_snapshot', {
            snapshotPath: this.path
        });
    }
    /**
     * Gets the current status of the stronghold.
     * @returns
     */
    getStatus() {
        return invoke('plugin:stronghold|get_status', {
            snapshotPath: this.path
        });
    }
    /**
     * Listen to status changes on the stronghold.
     * @param cb
     * @returns
     */
    onStatusChange(cb) {
        if (statusChangeListeners[this.path] === void 0) {
            statusChangeListeners[this.path] = [];
        }
        const id = crypto.getRandomValues(new Uint8Array(1))[0].toString();
        statusChangeListeners[this.path].push({
            id,
            cb
        });
        return () => {
            statusChangeListeners[this.path] = statusChangeListeners[this.path].filter(listener => listener.id !== id);
        };
    }
    /**
     * Starts the P2P communication system.
     * @returns
     */
    spawnCommunication() {
        return invoke('plugin:stronghold|spawn_communication', {
            snapshotPath: this.path
        }).then(() => new Communication(this.path));
    }
}

export { Communication, Location, RelayDirection, RemoteStore, RemoteVault, RequestPermission, Store, Stronghold, StrongholdFlag, Vault, setPasswordClearInterval };
