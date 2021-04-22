use iota_stronghold::{
    Location, ProcResult, Procedure, RecordHint, SLIP10DeriveInput, StrongholdFlags,
    VaultFlags,
};
use crypto::keys::slip10::Chain;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tauri::{async_runtime::Mutex, plugin::Plugin, InvokeMessage, Params, Window};

use std::{
    collections::HashMap,
    convert::{Into, TryInto},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

mod stronghold;
use stronghold::{Api, Status};

type Result<T> = std::result::Result<T, stronghold::Error>;

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
        counter: usize,
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
    let store = api.get_store(vault.name, array_into(vault.flags));
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
    flags: Option<Vec<VaultFlagsDto>>,
) -> Result<()> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let vault = api.get_vault(vault.name, array_into(vault.flags));
    vault
        .save_record(
            location.into(),
            record,
            record_hint.unwrap_or_else(default_record_hint),
            array_into(flags.unwrap_or_default()),
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
    let vault = api.get_vault(vault.name, array_into(vault.flags));
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
    let store = api.get_store(vault.name, array_into(vault.flags));
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
    let store = api.get_store(vault.name, array_into(vault.flags));
    store.remove_record(location.into()).await?;
    Ok(())
}

#[tauri::command]
async fn execute_procedure(
    snapshot_path: PathBuf,
    vault: VaultDto,
    procedure: ProcedureDto,
) -> Result<ProcResultDto> {
    let api_instances = api_instances().lock().await;
    let api = api_instances.get(&snapshot_path).unwrap();
    let vault = api.get_vault(vault.name, array_into(vault.flags));
    let result = vault.execute_procedure(procedure.into()).await?;

    let result = match result {
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

    Ok(result)
}

pub struct TauriStronghold<M: Params> {
    invoke_handler: Box<dyn Fn(InvokeMessage<M>) + Send + Sync>,
}

impl<M: Params> Default for TauriStronghold<M> {
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
                execute_procedure
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

#[derive(Serialize)]
struct StatusChangeEvent<'a> {
    #[serde(rename = "snapshotPath")]
    snapshot_path: &'a PathBuf,
    status: &'a stronghold::Status,
}

impl<M: Params> Plugin<M> for TauriStronghold<M> {
    fn name(&self) -> &'static str {
        "stronghold"
    }

    fn created(&mut self, window: Window<M>) {
        tauri::async_runtime::block_on(stronghold::on_status_change(
            move |snapshot_path, status| {
                let _ = window.emit(
                    &"stronghold://status-change".parse().unwrap_or_else(|_| {
                        panic!("Stronghold status change event not parsed by your Event struct")
                    }),
                    Some(StatusChangeEvent {
                        snapshot_path,
                        status,
                    }),
                );
            },
        ))
    }

    fn extend_api(&mut self, message: InvokeMessage<M>) {
        (self.invoke_handler)(message)
    }
}
