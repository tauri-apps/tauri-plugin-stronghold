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

fn array_into<R, T: Into<R>>(items: Vec<T>) -> Vec<R> {
    items.into_iter().map(|item| item.into()).collect()
}

#[derive(Deserialize)]
struct VaultDto {
    name: String,
}

fn default_record_hint() -> RecordHint {
    RecordHint::new([0; 24]).unwrap()
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

    fn extend_api(&mut self, invoke: Invoke<R>) {
        (self.invoke_handler)(invoke)
    }
}
