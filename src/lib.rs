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
use iota_stronghold::{
    procedures::{
        BIP39Generate, Chain, GenerateKey, KeyType, MnemonicLanguage, Slip10Derive, Slip10DeriveInput, Slip10Generate,
        StrongholdProcedure,
    },
};
use engine::vault::RecordHint;
pub mod stronghold;
use p2p::{Multiaddr, PeerId};

type Result<T> = std::result::Result<T, stronghold::Error>;

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
struct VaultDto {
    name: String,
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

fn default_record_hint() -> RecordHint {
    RecordHint::new([0; 24]).unwrap()
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
