use async_std::{
    sync::Mutex,
    task::{sleep, spawn},
};

use iota_stronghold as stronghold;
use stronghold::{
    procedures::{
        BIP39Generate, Chain, GenerateKey, KeyType, MnemonicLanguage, Slip10Derive, Slip10DeriveInput, Slip10Generate,
        StrongholdProcedure,
    },
    Client, ClientError, ClientVault, KeyProvider, Location, SnapshotPath, Store, Stronghold,
};

use once_cell::sync::{OnceCell};
use zeroize::Zeroize;

use std::{
    collections::{HashMap, HashSet},
    ops::DerefMut,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Parser)]
pub struct VaultLocation {
    #[clap(long, help = "The storage location inside the vault")]
    vault_path: String,

    #[clap(long, help = "The storage location for a record inside a vault")]
    record_path: String,
}

impl VaultLocation {
    fn from(vault: String, record: String) -> Self {
        Self {
            record_path: record,
            vault_path: vault,
        }
    }
    
    fn to_location(&self) -> Location {
        Location::Generic {
            record_path: self.record_path.clone().into_bytes().to_vec(),
            vault_path: self.vault_path.clone().into_bytes().to_vec(),
        }
    }
}

fn create_snapshot(path: String, client_path: String, output: VaultLocation, key: String) {
    let stronghold = Stronghold::default();

    let client_path = client_path.as_bytes().to_vec();

    let client = stronghold
        .create_client(client_path.clone())
        .expect("Cannot creat client");

    let output_location = output.to_location();

    let generate_key_procedure = GenerateKey {
        ty: KeyType::Ed25519,
        output: output_location,
    };

    client
        .execute_procedure(generate_key_procedure)
        .expect("Running procedure failed");

    stronghold
        .write_client(client_path)
        .expect("Store client state into snapshot state failed");
}
