use tauri::{plugin::Plugin, Invoke, Runtime};
use engine::vault::{Key};

use iota_stronghold as stronghold;
use stronghold::{
     Provider
};

use std::convert::{TryInto},

pub mod stronghold;

//struct api(Arc<Mutex<HashMap<Pathbuf , Api>>>) ;

pub struct TauriStronghold<R: Runtime> {
    invoke_handler: Box<dyn Fn(Invoke<R>) + Send + Sync>,
}

impl<R: Runtime> Default for TauriStronghold<R> {
    fn default() -> Self {
        Self {
            invoke_handler: Box::new(tauri::generate_handler![
              save_record
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

#[tauri::command]
async fn save_record() {
    
}

fn password_to_key(password: &str) -> Key<Provider> {
    let mut dk = [0; 64];
    // safe to unwrap (rounds > 0)
    crypto::keys::pbkdf::PBKDF2_HMAC_SHA512(password.as_bytes(), b"tauri", 100, &mut dk).unwrap();
    let key: [u8; 32] = dk[0..32][..].try_into().unwrap();
    Key::load(key.to_vec()) 
}
