use std::convert::{TryFrom, Infallible};
use crypto::hashes::{blake2b::Blake2b256, Digest};
use iota_stronghold as stronghold;
use stronghold::{
    procedures::{
        GenerateKey, KeyType,
        StrongholdProcedure,
    },
    Client, ClientError, KeyProvider, Location, SnapshotPath, Stronghold,
};
use engine::vault::{DbView, Key, RecordHint, RecordId, VaultId};
use utils::provider::Provider;

#[derive(Debug)]
pub struct VaultLocation {
    vault_path: String,
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

/// Calculates the Blake2b from a String
fn hash_blake2b(input: String) -> Vec<u8> {
    let mut hasher = Blake2b256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}

async fn create_snapshot(path: String, client_path: String, output: VaultLocation, key: String) {
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

async fn read_snapshot(path: String, client_path: String, key: String, private_key_location: VaultLocation) {
    let stronghold = Stronghold::default();
    let client_path = client_path.as_bytes().to_vec();
    let snapshot_path = SnapshotPath::from_path(path);

    // calculate hash from key
    let key = hash_blake2b(key);
    let keyprovider = KeyProvider::try_from(key).expect("Failed to load key");

    let client = stronghold
        .load_client_from_snapshot(client_path, &keyprovider, &snapshot_path)
        .expect("Could not load client from Snapshot");

    // get the public key
    let public_key_procedure = stronghold::procedures::PublicKey {
        ty: KeyType::Ed25519,
        private_key: private_key_location.to_location(),
    };

    let procedure_result = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure));

    let procedure_result = procedure_result.unwrap();
    let output: Vec<u8> = procedure_result.into();
}

async fn write_from_store(key: String, value: String) -> Result<(), ClientError> {
    let client = Client::default();
    let store = client.store();

    store.insert(key.as_bytes().to_vec(), value.as_bytes().to_vec(), None)?;

    Ok(())
}

async fn read_from_store(key: String) -> String {
    let client = Client::default();
    let store = client.store();
    
    let record = store.get(key.as_bytes()).unwrap() ;
    
    return String::from_utf8(record.unwrap()).unwrap();
}

async fn init_vault() {
  let mut view: DbView<Provider> = DbView::new();

  let key = Key::random();
  let vaulId = VaultId::random::<Provider>().unwrap();
  
   view.init_vault(&key, vaultId);
} 

async fn get_vault_value(key: Key, vault: VaultId, record: RecordId) -> Result<String, VaultError> {
  view.get_guard::<Infallible, _>(key, vault, record, |g| {
      
    Ok(g)
  })
} 

async fn write_vault_value(key: Key, vault: VaultId, record: RecordId, data: String,  record_hint: RecordHint) -> Result<(), RecordError> {
       // write to vault0 and record0
    view.write(key, vault, record, data, record_hint)?
}
