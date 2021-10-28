import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';

var RelayDirection;
(function (RelayDirection) {
    RelayDirection[RelayDirection["Dialing"] = 0] = "Dialing";
    RelayDirection[RelayDirection["Listening"] = 1] = "Listening";
    RelayDirection[RelayDirection["Both"] = 2] = "Both";
})(RelayDirection || (RelayDirection = {}));
var RequestPermission;
(function (RequestPermission) {
    RequestPermission[RequestPermission["CheckVault"] = 0] = "CheckVault";
    RequestPermission[RequestPermission["CheckRecord"] = 1] = "CheckRecord";
    RequestPermission[RequestPermission["WriteToStore"] = 2] = "WriteToStore";
    RequestPermission[RequestPermission["ReadFromStore"] = 3] = "ReadFromStore";
    RequestPermission[RequestPermission["DeleteFromStore"] = 4] = "DeleteFromStore";
    RequestPermission[RequestPermission["CreateNewVault"] = 5] = "CreateNewVault";
    RequestPermission[RequestPermission["WriteToVault"] = 6] = "WriteToVault";
    RequestPermission[RequestPermission["RevokeData"] = 7] = "RevokeData";
    RequestPermission[RequestPermission["GarbageCollect"] = 8] = "GarbageCollect";
    RequestPermission[RequestPermission["ListIds"] = 9] = "ListIds";
    RequestPermission[RequestPermission["ReadSnapshot"] = 10] = "ReadSnapshot";
    RequestPermission[RequestPermission["WriteSnapshot"] = 11] = "WriteSnapshot";
    RequestPermission[RequestPermission["FillSnapshot"] = 12] = "FillSnapshot";
    RequestPermission[RequestPermission["ClearCache"] = 13] = "ClearCache";
    RequestPermission[RequestPermission["ControlRequest"] = 14] = "ControlRequest";
})(RequestPermission || (RequestPermission = {}));
const statusChangeListeners = {};
listen('stronghold://status-change', event => {
    const { snapshotPath, status } = event.payload;
    for (const listener of (statusChangeListeners[snapshotPath] || [])) {
        listener.cb(status);
    }
});
function s4() {
    return Math.floor((1 + Math.random()) * 0x10000)
        .toString(16)
        .substring(1);
}
function uid() {
    return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
        s4() + '-' + s4() + s4() + s4();
}
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
class RemoteStore {
    constructor(path, peerId) {
        this.path = path;
        this.peerId = peerId;
    }
    get(location) {
        return invoke('plugin:stronghold|get_remote_store_record', {
            snapshotPath: this.path,
            peerId: this.peerId,
            location
        });
    }
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
class RemoteVault extends ProcedureExecutor {
    constructor(path, peerId) {
        super(true, {
            peerId
        });
        this.path = path;
        this.peerId = peerId;
    }
}
class Store {
    constructor(path, name, flags) {
        this.path = path;
        this.name = name;
        this.flags = flags;
    }
    get vault() {
        return {
            name: this.name,
            flags: this.flags
        };
    }
    get(location) {
        return invoke('plugin:stronghold|get_store_record', {
            snapshotPath: this.path,
            vault: this.vault,
            location
        });
    }
    insert(location, record, lifetime) {
        return invoke('plugin:stronghold|save_store_record', {
            snapshotPath: this.path,
            vault: this.vault,
            location,
            record,
            lifetime
        });
    }
    remove(location) {
        return invoke('plugin:stronghold|remove_store_record', {
            snapshotPath: this.path,
            vault: this.vault,
            location
        });
    }
}
class Vault extends ProcedureExecutor {
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
    get vault() {
        return {
            name: this.name,
            flags: this.flags
        };
    }
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
    remove(location, gc = true) {
        return invoke('plugin:stronghold|remove_record', {
            snapshotPath: this.path,
            vault: this.vault,
            location,
            gc
        });
    }
}
class Communication {
    constructor(path) {
        this.path = path;
    }
    stop() {
        return invoke('plugin:stronghold|stop_communication', {
            snapshotPath: this.path
        });
    }
    startListening(addr) {
        return invoke('plugin:stronghold|start_listening', {
            snapshotPath: this.path,
            addr
        });
    }
    getSwarmInfo() {
        return invoke('plugin:stronghold|get_swarm_info', { snapshotPath: this.path });
    }
    addPeer(peerId, addr, relayDirection) {
        return invoke('plugin:stronghold|add_peer', {
            snapshotPath: this.path,
            peerId,
            addr,
            relayDirection: relayDirection ? { type: RelayDirection[relayDirection] } : null
        });
    }
    changeRelayDirection(peerId, relayDirection) {
        return invoke('plugin:stronghold|change_relay_direction', {
            snapshotPath: this.path,
            peerId,
            relayDirection: { type: RelayDirection[relayDirection] }
        });
    }
    removeRelay(peerId) {
        return invoke('plugin:stronghold|remove_relay', {
            snapshotPath: this.path,
            peerId
        });
    }
    allowAllRequests(peers, setDefault = false) {
        return invoke('plugin:stronghold|allow_all_requests', {
            snapshotPath: this.path,
            peers,
            setDefault
        });
    }
    rejectAllRequests(peers, setDefault = false) {
        return invoke('plugin:stronghold|reject_all_requests', {
            snapshotPath: this.path,
            peers,
            setDefault
        });
    }
    allowRequests(peers, permissions, changeDefault = false) {
        return invoke('plugin:stronghold|allow_requests', {
            snapshotPath: this.path,
            peers,
            requests: permissions.map(p => ({ type: RequestPermission[p] })),
            changeDefault
        });
    }
    rejectRequests(peers, permissions, changeDefault = false) {
        return invoke('plugin:stronghold|reject_requests', {
            snapshotPath: this.path,
            peers,
            requests: permissions.map(p => ({ type: RequestPermission[p] })),
            changeDefault
        });
    }
    removeFirewallRules(peers) {
        return invoke('plugin:stronghold|remove_firewall_rules', {
            snapshotPath: this.path,
            peers
        });
    }
    getRemoteVault(peerId) {
        return new RemoteVault(this.path, peerId);
    }
    getRemoteStore(peerId) {
        return new RemoteStore(this.path, peerId);
    }
}
class Stronghold {
    constructor(path, password) {
        this.path = path;
        this.reload(password);
    }
    reload(password) {
        return invoke('plugin:stronghold|init', {
            snapshotPath: this.path,
            password
        });
    }
    unload() {
        return invoke('plugin:stronghold|destroy', {
            snapshotPath: this.path
        });
    }
    getVault(name, flags) {
        return new Vault(this.path, name, flags);
    }
    getStore(name, flags) {
        return new Store(this.path, name, flags);
    }
    save() {
        return invoke('plugin:stronghold|save_snapshot', {
            snapshotPath: this.path
        });
    }
    getStatus() {
        return invoke('plugin:stronghold|get_status', {
            snapshotPath: this.path
        });
    }
    onStatusChange(cb) {
        if (statusChangeListeners[this.path] === void 0) {
            statusChangeListeners[this.path] = [];
        }
        const id = uid();
        statusChangeListeners[this.path].push({
            id,
            cb
        });
        return () => {
            statusChangeListeners[this.path] = statusChangeListeners[this.path].filter(listener => listener.id !== id);
        };
    }
    spawnCommunication() {
        return invoke('plugin:stronghold|spawn_communication', {
            snapshotPath: this.path
        }).then(() => new Communication(this.path));
    }
}

export { Communication, Location, RelayDirection, RemoteStore, RemoteVault, RequestPermission, Store, Stronghold, StrongholdFlag, Vault, setPasswordClearInterval };
