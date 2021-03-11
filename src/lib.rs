use async_std::task::block_on;
use iota_stronghold::{
    hd::Chain, Location, ProcResult, Procedure, RecordHint, SLIP10DeriveInput, StrongholdFlags,
    VaultFlags,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use std::{
    collections::HashMap,
    convert::{Into, TryInto},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

mod stronghold;
use stronghold::Api;

fn api_instances() -> &'static Arc<Mutex<HashMap<PathBuf, Api>>> {
    static API: Lazy<Arc<Mutex<HashMap<PathBuf, Api>>>> = Lazy::new(Default::default);
    &API
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
enum StrongholdFlagDto {
    IsReadable(bool),
}

impl Into<StrongholdFlags> for StrongholdFlagDto {
    fn into(self) -> StrongholdFlags {
        match self {
            Self::IsReadable(flag) => StrongholdFlags::IsReadable(flag),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
enum VaultFlagsDto {}

impl Into<VaultFlags> for VaultFlagsDto {
    fn into(self) -> VaultFlags {
        unimplemented!()
    }
}

fn array_into<R, T: Into<R>>(items: Vec<T>) -> Vec<R> {
    items.into_iter().map(|item| item.into()).collect()
}

#[derive(Deserialize)]
struct VaultDto {
    name: String,
    #[serde(default)]
    flags: Vec<StrongholdFlagDto>,
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
enum LocationDto {
    Generic {
        vault: String,
        record: String,
    },
    Counter {
        vault: String,
        counter: Option<usize>,
    },
}

impl Into<Location> for LocationDto {
    fn into(self) -> Location {
        match self {
            Self::Generic { vault, record } => Location::generic(vault, record),
            Self::Counter { vault, counter } => Location::counter(vault, counter),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
enum SLIP10DeriveInputDto {
    Seed(LocationDto),
    Key(LocationDto),
}

impl Into<SLIP10DeriveInput> for SLIP10DeriveInputDto {
    fn into(self) -> SLIP10DeriveInput {
        match self {
            Self::Seed(location) => SLIP10DeriveInput::Seed(location.into()),
            Self::Key(location) => SLIP10DeriveInput::Key(location.into()),
        }
    }
}

fn default_record_hint() -> RecordHint {
    RecordHint::new([0; 24]).unwrap()
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
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

impl Into<Procedure> for ProcedureDto {
    fn into(self) -> Procedure {
        match self {
            Self::SLIP10Generate {
                output,
                hint,
                size_bytes,
            } => Procedure::SLIP10Generate {
                output: output.into(),
                hint,
                size_bytes,
            },
            Self::SLIP10Derive {
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
            Self::BIP39Recover {
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
            Self::BIP39Generate {
                passphrase,
                output,
                hint,
            } => Procedure::BIP39Generate {
                passphrase,
                output: output.into(),
                hint,
            },
            Self::BIP39MnemonicSentence { seed } => {
                Procedure::BIP39MnemonicSentence { seed: seed.into() }
            }
            Self::Ed25519PublicKey { private_key } => Procedure::Ed25519PublicKey {
                private_key: private_key.into(),
            },
            Self::Ed25519Sign { private_key, msg } => Procedure::Ed25519Sign {
                private_key: private_key.into(),
                msg: msg.as_bytes().to_vec(),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
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

#[derive(Deserialize)]
#[serde(tag = "cmd")]
enum StrongholdCmd {
    StrongholdInit {
        #[serde(rename = "snapshotPath")]
        snapshot_path: PathBuf,
        password: String,
        callback: String,
        error: String,
    },
    StrongholdDestroy {
        #[serde(rename = "snapshotPath")]
        snapshot_path: PathBuf,
        callback: String,
        error: String,
    },
    StrongholdSetPasswordClearInterval {
        interval: Duration,
    },
    StrongholdSnapshotSave {
        #[serde(rename = "snapshotPath")]
        snapshot_path: PathBuf,
        callback: String,
        error: String,
    },
    StrongholdGetStatus {
        #[serde(rename = "snapshotPath")]
        snapshot_path: PathBuf,
        callback: String,
        error: String,
    },
    GetStrongholdStoreRecord {
        #[serde(rename = "snapshotPath")]
        snapshot_path: PathBuf,
        vault: VaultDto,
        location: LocationDto,
        callback: String,
        error: String,
    },
    SaveStrongholdRecord {
        #[serde(rename = "snapshotPath")]
        snapshot_path: PathBuf,
        vault: VaultDto,
        location: LocationDto,
        record: String,
        #[serde(rename = "recordHint", default = "default_record_hint")]
        record_hint: RecordHint,
        #[serde(default)]
        flags: Vec<VaultFlagsDto>,
        callback: String,
        error: String,
    },
    RemoveStrongholdRecord {
        #[serde(rename = "snapshotPath")]
        snapshot_path: PathBuf,
        vault: VaultDto,
        location: LocationDto,
        #[serde(default)]
        gc: bool,
        callback: String,
        error: String,
    },
    SaveStrongholdStoreRecord {
        #[serde(rename = "snapshotPath")]
        snapshot_path: PathBuf,
        vault: VaultDto,
        location: LocationDto,
        record: String,
        lifetime: Option<Duration>,
        callback: String,
        error: String,
    },
    RemoveStrongholdStoreRecord {
        #[serde(rename = "snapshotPath")]
        snapshot_path: PathBuf,
        vault: VaultDto,
        location: LocationDto,
        callback: String,
        error: String,
    },
    ExecuteStrongholdProcedure {
        #[serde(rename = "snapshotPath")]
        snapshot_path: PathBuf,
        vault: VaultDto,
        procedure: ProcedureDto,
        callback: String,
        error: String,
    },
}

pub struct TauriStronghold;

fn password_to_key(password: &str) -> [u8; 32] {
    let mut dk = [0; 64];
    // safe to unwrap (rounds > 0)
    crypto::keys::pbkdf::PBKDF2_HMAC_SHA512(password.as_bytes(), b"tauri", 100, &mut dk).unwrap();
    let key: [u8; 32] = dk[0..32][..].try_into().unwrap();
    key
}

#[derive(Serialize)]
struct StatusChangeEvent<'a> {
    #[serde(rename = "snapshotPath")]
    snapshot_path: &'a PathBuf,
    status: &'a stronghold::Status,
}

impl tauri::plugin::Plugin for TauriStronghold {
    fn ready(&self, webview: &mut tauri::Webview<'_>) {
        let mut webview_ = webview.as_mut();
        block_on(stronghold::on_status_change(
            move |snapshot_path, status| {
                let _ = tauri::event::emit(
                    &mut webview_,
                    "stronghold:status-change",
                    Some(StatusChangeEvent {
                        snapshot_path,
                        status,
                    }),
                );
            },
        ))
    }

    fn extend_api(&self, webview: &mut tauri::Webview<'_>, payload: &str) -> Result<bool, String> {
        use StrongholdCmd::*;
        match serde_json::from_str(payload) {
            Err(e) => Err(e.to_string()),
            Ok(command) => {
                match command {
                    StrongholdInit {
                        snapshot_path,
                        password,
                        callback,
                        error,
                    } => {
                        let api = Api::new(snapshot_path.clone());
                        let mut api_instances_ = api_instances().lock().unwrap();
                        api_instances_.insert(snapshot_path.clone(), api);
                        drop(api_instances_);
                        tauri::execute_promise(
                            webview,
                            move || {
                                let api_instances = api_instances().lock().unwrap();
                                let api = api_instances.get(&snapshot_path).unwrap();
                                block_on(api.load(&password_to_key(&password)))?;
                                Ok(())
                            },
                            callback,
                            error,
                        );
                    }
                    StrongholdDestroy {
                        snapshot_path,
                        callback,
                        error,
                    } => {
                        tauri::execute_promise(
                            webview,
                            move || {
                                let api_instances = api_instances().lock().unwrap();
                                let api = api_instances.get(&snapshot_path).unwrap();
                                block_on(api.unload(true))?;
                                Ok(())
                            },
                            callback,
                            error,
                        );
                    }
                    StrongholdSetPasswordClearInterval { interval } => {
                        block_on(stronghold::set_password_clear_interval(interval));
                    }
                    StrongholdSnapshotSave {
                        snapshot_path,
                        callback,
                        error,
                    } => {
                        tauri::execute_promise(
                            webview,
                            move || {
                                let api_instances = api_instances().lock().unwrap();
                                let api = api_instances.get(&snapshot_path).unwrap();
                                block_on(api.save())?;
                                Ok(())
                            },
                            callback,
                            error,
                        );
                    }
                    StrongholdGetStatus {
                        snapshot_path,
                        callback,
                        error,
                    } => {
                        tauri::execute_promise(
                            webview,
                            move || {
                                let api_instances = api_instances().lock().unwrap();
                                let api = api_instances.get(&snapshot_path).unwrap();
                                let status = block_on(api.get_status());
                                Ok(status)
                            },
                            callback,
                            error,
                        );
                    }
                    GetStrongholdStoreRecord {
                        snapshot_path,
                        vault,
                        location,
                        callback,
                        error,
                    } => {
                        tauri::execute_promise(
                            webview,
                            move || {
                                let api_instances = api_instances().lock().unwrap();
                                let api = api_instances.get(&snapshot_path).unwrap();
                                let store = api.get_store(vault.name, array_into(vault.flags));
                                let record = block_on(store.get_record(location.into()))?;
                                Ok(record)
                            },
                            callback,
                            error,
                        );
                    }
                    SaveStrongholdRecord {
                        snapshot_path,
                        vault,
                        location,
                        record,
                        record_hint,
                        flags,
                        callback,
                        error,
                    } => {
                        tauri::execute_promise(
                            webview,
                            move || {
                                let api_instances = api_instances().lock().unwrap();
                                let api = api_instances.get(&snapshot_path).unwrap();
                                let vault = api.get_vault(vault.name, array_into(vault.flags));
                                block_on(vault.save_record(
                                    location.into(),
                                    record,
                                    record_hint,
                                    array_into(flags),
                                ))?;
                                Ok(())
                            },
                            callback,
                            error,
                        );
                    }
                    RemoveStrongholdRecord {
                        snapshot_path,
                        vault,
                        location,
                        gc,
                        callback,
                        error,
                    } => {
                        tauri::execute_promise(
                            webview,
                            move || {
                                let api_instances = api_instances().lock().unwrap();
                                let api = api_instances.get(&snapshot_path).unwrap();
                                let vault = api.get_vault(vault.name, array_into(vault.flags));
                                block_on(vault.remove_record(location.into(), gc))?;
                                Ok(())
                            },
                            callback,
                            error,
                        );
                    }
                    SaveStrongholdStoreRecord {
                        snapshot_path,
                        vault,
                        location,
                        record,
                        lifetime,
                        callback,
                        error,
                    } => {
                        tauri::execute_promise(
                            webview,
                            move || {
                                let api_instances = api_instances().lock().unwrap();
                                let api = api_instances.get(&snapshot_path).unwrap();
                                let store = api.get_store(vault.name, array_into(vault.flags));
                                block_on(store.save_record(location.into(), record, lifetime))?;
                                Ok(())
                            },
                            callback,
                            error,
                        );
                    }
                    RemoveStrongholdStoreRecord {
                        snapshot_path,
                        vault,
                        location,
                        callback,
                        error,
                    } => {
                        tauri::execute_promise(
                            webview,
                            move || {
                                let api_instances = api_instances().lock().unwrap();
                                let api = api_instances.get(&snapshot_path).unwrap();
                                let store = api.get_store(vault.name, array_into(vault.flags));
                                block_on(store.remove_record(location.into()))?;
                                Ok(())
                            },
                            callback,
                            error,
                        );
                    }
                    ExecuteStrongholdProcedure {
                        snapshot_path,
                        vault,
                        procedure,
                        callback,
                        error,
                    } => {
                        tauri::execute_promise(
                            webview,
                            move || {
                                let api_instances = api_instances().lock().unwrap();
                                let api = api_instances.get(&snapshot_path).unwrap();
                                let vault = api.get_vault(vault.name, array_into(vault.flags));
                                let result = block_on(vault.execute_procedure(procedure.into()))?;

                                let result = match result {
                                    ProcResult::SLIP10Generate(status) => {
                                        stronghold::stronghold_response_to_result(status)?;
                                        ProcResultDto::SLIP10Generate
                                    }
                                    ProcResult::SLIP10Derive(status) => {
                                        let chain_code =
                                            stronghold::stronghold_response_to_result(status)?;
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
                                        let sentence =
                                            stronghold::stronghold_response_to_result(status)?;
                                        ProcResultDto::BIP39MnemonicSentence(sentence)
                                    }
                                    ProcResult::Ed25519PublicKey(status) => {
                                        let public_key =
                                            stronghold::stronghold_response_to_result(status)?;
                                        ProcResultDto::Ed25519PublicKey(hex::encode(public_key))
                                    }
                                    ProcResult::Ed25519Sign(status) => {
                                        let signature =
                                            stronghold::stronghold_response_to_result(status)?;
                                        ProcResultDto::Ed25519Sign(hex::encode(signature))
                                    }
                                };

                                Ok(result)
                            },
                            callback,
                            error,
                        );
                    }
                }
                Ok(true)
            }
        }
    }
}
