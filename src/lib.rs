use crypto::keys::slip10::Chain;
pub use iota_stronghold::Location;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tauri::{async_runtime::Mutex, plugin::Plugin, Invoke, Runtime, Window};

use std::{
    collections::HashMap,
    convert::{Into, TryInto},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

/// The stronghold interface.
use stronghold::{
    procedures::{
        BIP39Generate, Chain, GenerateKey, KeyType, MnemonicLanguage, Slip10Derive, Slip10DeriveInput, Slip10Generate,
        StrongholdProcedure,
    },
};
pub mod stronghold;
use stronghold::{Api, Status, SwarmInfo};
use p2p::{Multiaddr, PeerId};

type Result<T> = std::result::Result<T, stronghold::Error>;

fn api_instances() -> &'static Arc<Mutex<HashMap<PathBuf, Api>>> {
    static API: Lazy<Arc<Mutex<HashMap<PathBuf, Api>>>> = Lazy::new(Default::default);
    &API
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwarmInfoDto {
    pub peer_id: String,
    pub listening_addresses: Vec<Multiaddr>,
}

impl From<SwarmInfo> for SwarmInfoDto {
    fn from(info: SwarmInfo) -> Self {
        Self {
            peer_id: info.peer_id.to_string(),
            listening_addresses: info.listening_addresses,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum RelayDirectionDto {
    Dialing,
    Listening,
    Both,
}

impl From<RelayDirectionDto> for RelayDirection {
    fn from(direction: RelayDirectionDto) -> Self {
        match direction {
            RelayDirectionDto::Dialing => Self::Dialing,
            RelayDirectionDto::Listening => Self::Listening,
            RelayDirectionDto::Both => Self::Both,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
enum SHRequestPermissionDto {
    CheckVault,
    CheckRecord,
    WriteToStore,
    ReadFromStore,
    DeleteFromStore,
    CreateNewVault,
    WriteToVault,
    RevokeData,
    GarbageCollect,
    ListIds,
    ReadSnapshot,
    WriteSnapshot,
    FillSnapshot,
    ClearCache,
    ControlRequest,
}

impl From<SHRequestPermissionDto> for SHRequestPermission {
    fn from(direction: SHRequestPermissionDto) -> Self {
        match direction {
            SHRequestPermissionDto::CheckVault => Self::CheckVault,
            SHRequestPermissionDto::CheckRecord => Self::CheckRecord,
            SHRequestPermissionDto::WriteToStore => Self::WriteToStore,
            SHRequestPermissionDto::ReadFromStore => Self::ReadFromStore,
            SHRequestPermissionDto::DeleteFromStore => Self::DeleteFromStore,
            SHRequestPermissionDto::CreateNewVault => Self::CreateNewVault,
            SHRequestPermissionDto::WriteToVault => Self::WriteToVault,
            SHRequestPermissionDto::RevokeData => Self::RevokeData,
            SHRequestPermissionDto::GarbageCollect => Self::GarbageCollect,
            SHRequestPermissionDto::ListIds => Self::ListIds,
            SHRequestPermissionDto::ReadSnapshot => Self::ReadSnapshot,
            SHRequestPermissionDto::WriteSnapshot => Self::WriteSnapshot,
            SHRequestPermissionDto::FillSnapshot => Self::FillSnapshot,
            SHRequestPermissionDto::ClearCache => Self::ClearCache,
            SHRequestPermissionDto::ControlRequest => Self::ControlRequest,
        }
    }
}

fn array_into<R, T: Into<R>>(items: Vec<T>) -> Vec<R> {
    items.into_iter().map(|item| item.into()).collect()
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
enum LocationDto {
    Generic { vault: String, record: String },
    Counter { vault: String, counter: usize },
}

impl From<LocationDto> for Location {
    fn from(dto: LocationDto) -> Location {
        match dto {
            LocationDto::Generic { vault, record } => Location::generic(vault, record),
            LocationDto::Counter { vault, counter } => Location::counter(vault, counter),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
#[allow(clippy::upper_case_acronyms)]
enum SLIP10DeriveInputDto {
    Seed(LocationDto),
    Key(LocationDto),
}

impl From<SLIP10DeriveInputDto> for SLIP10DeriveInput {
    fn from(dto: SLIP10DeriveInputDto) -> SLIP10DeriveInput {
        match dto {
            SLIP10DeriveInputDto::Seed(location) => SLIP10DeriveInput::Seed(location.into()),
            SLIP10DeriveInputDto::Key(location) => SLIP10DeriveInput::Key(location.into()),
        }
    }
}

fn default_record_hint() -> RecordHint {
    RecordHint::new([0; 24]).unwrap()
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
#[allow(clippy::upper_case_acronyms)]
enum ProcedureDto {
    SLIP10Generate {
        output: LocationDto,
        #[serde(default = "default_record_hint")]
        hint: RecordHint,
        #[serde(rename = "sizeBytes")]
        size_bytes: Option<usize>,
    },
    SLIP10Derive {
        chain: Vec<u32>,
        input: SLIP10DeriveInputDto,
        output: LocationDto,
        #[serde(default = "default_record_hint")]
        hint: RecordHint,
    },
    BIP39Recover {
        mnemonic: String,
        passphrase: Option<String>,
        output: LocationDto,
        #[serde(default = "default_record_hint")]
        hint: RecordHint,
    },
    BIP39Generate {
        passphrase: Option<String>,
        output: LocationDto,
        #[serde(default = "default_record_hint")]
        hint: RecordHint,
    },
    BIP39MnemonicSentence {
        seed: LocationDto,
    },
    Ed25519PublicKey {
        #[serde(rename = "privateKey")]
        private_key: LocationDto,
    },
    Ed25519Sign {
        #[serde(rename = "privateKey")]
        private_key: LocationDto,
        msg: String,
    },
}

impl From<ProcedureDto> for Procedure {
    fn from(dto: ProcedureDto) -> Procedure {
        match dto {
            ProcedureDto::SLIP10Generate {
                output,
                hint,
                size_bytes,
            } => Procedure::SLIP10Generate {
                output: output.into(),
                hint,
                size_bytes,
            },
            ProcedureDto::SLIP10Derive {
                chain,
                input,
                output,
                hint,
            } => Procedure::SLIP10Derive {
                chain: Chain::from_u32_hardened(chain),
                input: input.into(),
                output: output.into(),
                hint,
            },
            ProcedureDto::BIP39Recover {
                mnemonic,
                passphrase,
                output,
                hint,
            } => Procedure::BIP39Recover {
                mnemonic,
                passphrase,
                output: output.into(),
                hint,
            },
            ProcedureDto::BIP39Generate {
                passphrase,
                output,
                hint,
            } => Procedure::BIP39Generate {
                passphrase,
                output: output.into(),
                hint,
            },
            ProcedureDto::BIP39MnemonicSentence { seed } => {
                Procedure::BIP39MnemonicSentence { seed: seed.into() }
            }
            ProcedureDto::Ed25519PublicKey { private_key } => Procedure::Ed25519PublicKey {
                private_key: private_key.into(),
            },
            ProcedureDto::Ed25519Sign { private_key, msg } => Procedure::Ed25519Sign {
                private_key: private_key.into(),
                msg: msg.as_bytes().to_vec(),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
#[allow(clippy::upper_case_acronyms)]
pub enum ProcResultDto {
    /// Return from generating a `SLIP10` seed.
    SLIP10Generate,
    /// Returns the public key derived from the `SLIP10Derive` call.
    SLIP10Derive(String),
    /// `BIP39Recover` return value.
    BIP39Recover,
    /// `BIP39Generate` return value.
    BIP39Generate,
    /// `BIP39MnemonicSentence` return value. Returns the mnemonic sentence for the corresponding seed.
    BIP39MnemonicSentence(String),
    /// Return value for `Ed25519PublicKey`. Returns an Ed25519 public key.
    Ed25519PublicKey(String),
    /// Return value for `Ed25519Sign`. Returns an Ed25519 signature.
    Ed25519Sign(String),
}

#[tauri::command]
async fn init(snapshot_path: PathBuf, password: String) -> Result<()> {
    let api = Api::new(snapshot_path.clone());
    api_instances()
        .lock()
        .await
        .insert(snapshot_path.clone(), api);
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    api.load(password_to_key(&password)).await?;
    Ok(())
}

#[tauri::command]
async fn set_password_clear_interval(interval: Duration) {
    stronghold::set_password_clear_interval(interval).await;
}

#[tauri::command]
async fn destroy(snapshot_path: PathBuf) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    api.unload(true).await?;
    Ok(())
}

#[tauri::command]
async fn save_snapshot(snapshot_path: PathBuf) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    api.save().await?;
    Ok(())
}

#[tauri::command]
async fn get_status(snapshot_path: PathBuf) -> Result<Status> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let status = api.get_status().await;
    Ok(status)
}

#[tauri::command]
async fn get_store_record(
    snapshot_path: PathBuf,
    vault: VaultDto,
    location: LocationDto,
) -> Result<String> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let store = api.get_store(vault.name);
    let record = store.get_record(location.into()).await?;
    Ok(record)
}

#[tauri::command]
async fn save_record(
    snapshot_path: PathBuf,
    vault: VaultDto,
    location: LocationDto,
    record: String,
    record_hint: Option<RecordHint>,
) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let vault = api.get_vault(vault.name);
    vault
        .save_record(
            location.into(),
            record,
            record_hint.unwrap_or_else(default_record_hint),
        )
        .await?;
    Ok(())
}

#[tauri::command]
async fn remove_record(
    snapshot_path: PathBuf,
    vault: VaultDto,
    location: LocationDto,
    gc: bool,
) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let vault = api.get_vault(vault.name);
    vault.remove_record(location.into(), gc).await?;
    Ok(())
}

#[tauri::command]
async fn save_store_record(
    snapshot_path: PathBuf,
    vault: VaultDto,
    location: LocationDto,
    record: String,
    lifetime: Option<Duration>,
) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let store = api.get_store(vault.name);
    store.save_record(location.into(), record, lifetime).await?;
    Ok(())
}

#[tauri::command]
async fn remove_store_record(
    snapshot_path: PathBuf,
    vault: VaultDto,
    location: LocationDto,
) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let store = api.get_store(vault.name);
    store.remove_record(location.into()).await?;
    Ok(())
}

fn map_result(result: ProcResult) -> Result<ProcResultDto> {
    let r = match result {
        ProcResult::SLIP10Generate(status) => {
            stronghold::stronghold_response_to_result(status)?;
            ProcResultDto::SLIP10Generate
        }
        ProcResult::SLIP10Derive(status) => {
            let chain_code = stronghold::stronghold_response_to_result(status)?;
            ProcResultDto::SLIP10Derive(hex::encode(chain_code))
        }
        ProcResult::BIP39Recover(status) => {
            stronghold::stronghold_response_to_result(status)?;
            ProcResultDto::BIP39Recover
        }
        ProcResult::BIP39Generate(status) => {
            stronghold::stronghold_response_to_result(status)?;
            ProcResultDto::BIP39Generate
        }
        ProcResult::BIP39MnemonicSentence(status) => {
            let sentence = stronghold::stronghold_response_to_result(status)?;
            ProcResultDto::BIP39MnemonicSentence(sentence)
        }
        ProcResult::Ed25519PublicKey(status) => {
            let public_key = stronghold::stronghold_response_to_result(status)?;
            ProcResultDto::Ed25519PublicKey(hex::encode(public_key))
        }
        ProcResult::Ed25519Sign(status) => {
            let signature = stronghold::stronghold_response_to_result(status)?;
            ProcResultDto::Ed25519Sign(hex::encode(signature))
        }
        ProcResult::Error(e) => {
            return Err(stronghold::Error::FailedToPerformAction(e));
        }
    };
    Ok(r)
}

#[tauri::command]
async fn execute_procedure(
    snapshot_path: PathBuf,
    vault: VaultDto,
    procedure: ProcedureDto,
) -> Result<ProcResultDto> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let vault = api.get_vault(vault.name);
    let result = vault.execute_procedure(procedure.into()).await?;
    map_result(result)
}

#[tauri::command]
async fn spawn_communication(snapshot_path: PathBuf) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    api.spawn_communication().await
}

#[tauri::command]
async fn stop_communication(snapshot_path: PathBuf) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    api.stop_communication().await
}

#[tauri::command]
async fn start_listening(snapshot_path: PathBuf, addr: Option<Multiaddr>) -> Result<Multiaddr> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    api.start_listening(addr).await
}

#[tauri::command]
async fn get_swarm_info(snapshot_path: PathBuf) -> Result<SwarmInfoDto> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    api.get_swarm_info().await.map(Into::into)
}

#[tauri::command]
async fn add_peer(
    snapshot_path: PathBuf,
    peer_id: String,
    addr: Option<Multiaddr>,
    relay_direction: Option<RelayDirectionDto>,
) -> Result<String> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    api.add_peer(
        PeerId::from_str(&peer_id).map_err(|e| stronghold::Error::InvalidPeer(Box::new(e)))?,
        addr,
        relay_direction.map(Into::into),
    )
    .await
    .map(|peer| peer.to_string())
}

#[tauri::command]
async fn change_relay_direction(
    snapshot_path: PathBuf,
    peer_id: String,
    relay_direction: RelayDirectionDto,
) -> Result<String> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    api.change_relay_direction(
        PeerId::from_str(&peer_id).map_err(|e| stronghold::Error::InvalidPeer(Box::new(e)))?,
        relay_direction.into(),
    )
    .await
    .map(|peer| peer.to_string())
}

#[tauri::command]
async fn remove_relay(snapshot_path: PathBuf, peer_id: String) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    api.remove_relay(
        PeerId::from_str(&peer_id).map_err(|e| stronghold::Error::InvalidPeer(Box::new(e)))?,
    )
    .await
}

#[tauri::command]
async fn allow_all_requests(
    snapshot_path: PathBuf,
    peers: Vec<String>,
    set_default: bool,
) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let mut parsed_peers = Vec::new();
    for peer_id in peers {
        parsed_peers.push(
            PeerId::from_str(&peer_id).map_err(|e| stronghold::Error::InvalidPeer(Box::new(e)))?,
        );
    }
    api.allow_all_requests(parsed_peers, set_default).await
}

#[tauri::command]
async fn reject_all_requests(
    snapshot_path: PathBuf,
    peers: Vec<String>,
    set_default: bool,
) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let mut parsed_peers = Vec::new();
    for peer_id in peers {
        parsed_peers.push(
            PeerId::from_str(&peer_id).map_err(|e| stronghold::Error::InvalidPeer(Box::new(e)))?,
        );
    }
    api.reject_all_requests(parsed_peers, set_default).await
}

#[tauri::command]
async fn allow_requests(
    snapshot_path: PathBuf,
    peers: Vec<String>,
    change_default: bool,
    requests: Vec<SHRequestPermissionDto>,
) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let mut parsed_peers = Vec::new();
    for peer_id in peers {
        parsed_peers.push(
            PeerId::from_str(&peer_id).map_err(|e| stronghold::Error::InvalidPeer(Box::new(e)))?,
        );
    }
    api.allow_requests(
        parsed_peers,
        change_default,
        requests.into_iter().map(Into::into).collect(),
    )
    .await
}

#[tauri::command]
async fn reject_requests(
    snapshot_path: PathBuf,
    peers: Vec<String>,
    change_default: bool,
    requests: Vec<SHRequestPermissionDto>,
) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let mut parsed_peers = Vec::new();
    for peer_id in peers {
        parsed_peers.push(
            PeerId::from_str(&peer_id).map_err(|e| stronghold::Error::InvalidPeer(Box::new(e)))?,
        );
    }
    api.reject_requests(
        parsed_peers,
        change_default,
        requests.into_iter().map(Into::into).collect(),
    )
    .await
}

#[tauri::command]
async fn remove_firewall_rules(snapshot_path: PathBuf, peers: Vec<String>) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let mut parsed_peers = Vec::new();
    for peer_id in peers {
        parsed_peers.push(
            PeerId::from_str(&peer_id).map_err(|e| stronghold::Error::InvalidPeer(Box::new(e)))?,
        );
    }
    api.remove_firewall_rules(parsed_peers).await
}

#[tauri::command]
async fn get_remote_store_record(
    snapshot_path: PathBuf,
    peer_id: String,
    location: LocationDto,
) -> Result<String> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let store = api.get_remote_store(
        PeerId::from_str(&peer_id).map_err(|e| stronghold::Error::InvalidPeer(Box::new(e)))?,
    );
    let record = store.get_record(location.into()).await?;
    Ok(record)
}

#[tauri::command]
async fn save_remote_store_record(
    snapshot_path: PathBuf,
    peer_id: String,
    location: LocationDto,
    record: String,
    lifetime: Option<Duration>,
) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let store = api.get_remote_store(
        PeerId::from_str(&peer_id).map_err(|e| stronghold::Error::InvalidPeer(Box::new(e)))?,
    );
    store.save_record(location.into(), record, lifetime).await?;
    Ok(())
}

#[tauri::command]
async fn execute_remote_procedure(
    snapshot_path: PathBuf,
    peer_id: String,
    procedure: ProcedureDto,
) -> Result<ProcResultDto> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let vault = api.get_remote_vault(
        PeerId::from_str(&peer_id).map_err(|e| stronghold::Error::InvalidPeer(Box::new(e)))?,
    );
    let result = vault.execute_procedure(procedure.into()).await?;
    map_result(result)
}

pub struct TauriStronghold<R: Runtime> {
    invoke_handler: Box<dyn Fn(Invoke<R>) + Send + Sync>,
}

impl<R: Runtime> Default for TauriStronghold<R> {
    fn default() -> Self {
        Self {
            invoke_handler: Box::new(tauri::generate_handler![
                init,
                set_password_clear_interval,
                destroy,
                save_snapshot,
                get_status,
                get_store_record,
                save_record,
                remove_record,
                save_store_record,
                remove_store_record,
                execute_procedure,
                spawn_communication,
                stop_communication,
                start_listening,
                get_swarm_info,
                add_peer,
                change_relay_direction,
                remove_relay,
                allow_all_requests,
                reject_all_requests,
                allow_requests,
                reject_requests,
                remove_firewall_rules,
                get_remote_store_record,
                save_remote_store_record,
                execute_remote_procedure
            ]),
        }
    }
}

fn password_to_key(password: &str) -> Vec<u8> {
    let mut dk = [0; 64];
    // safe to unwrap (rounds > 0)
    crypto::keys::pbkdf::PBKDF2_HMAC_SHA512(password.as_bytes(), b"tauri", 100, &mut dk).unwrap();
    let key: [u8; 32] = dk[0..32][..].try_into().unwrap();
    key.to_vec()
}

#[derive(Serialize, Clone)]
struct StatusChangeEvent<'a> {
    #[serde(rename = "snapshotPath")]
    snapshot_path: PathBuf,
    status: &'a stronghold::Status,
}

impl<R: Runtime> Plugin<R> for TauriStronghold<R> {
    fn name(&self) -> &'static str {
        "stronghold"
    }

    fn created(&mut self, window: Window<R>) {
        tauri::async_runtime::block_on(stronghold::on_status_change(
            move |snapshot_path, status| {
                let _ = window.emit(
                    "stronghold://status-change",
                    Some(StatusChangeEvent {
                        snapshot_path: snapshot_path.to_path_buf(),
                        status,
                    }),
                );
            },
        ))
    }

    fn extend_api(&mut self, invoke: Invoke<R>) {
        (self.invoke_handler)(invoke)
    }
}
