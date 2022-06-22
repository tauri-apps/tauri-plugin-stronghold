use crypto::hashes::{blake2b::Blake2b256, Digest};
use iota_stronghold as stronghold;
use stronghold::{
    procedures::{
        BIP39Generate, Chain, GenerateKey, KeyType, MnemonicLanguage, Slip10Derive, Slip10DeriveInput, Slip10Generate,
        StrongholdProcedure,
    },
    Client, ClientError, ClientVault, KeyProvider, Location, SnapshotPath, Store, Stronghold,
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
