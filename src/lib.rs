pub use iota_stronghold::Location;
use serde::{Serialize};
use tauri::{plugin::Plugin, Invoke, Runtime};

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

impl<R: Runtime> Plugin<R> for TauriStronghold<R> {
    fn name(&self) -> &'static str {
        "stronghold"
    }

    fn extend_api(&mut self, invoke: Invoke<R>) {
        (self.invoke_handler)(invoke)
    }
}
