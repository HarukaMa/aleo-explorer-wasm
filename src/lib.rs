use std::str::FromStr;

use snarkvm_console_account::ViewKey;
use snarkvm_console_network::{traits::ToBits, Network, Testnet3};
use snarkvm_console_program::{Ciphertext, Identifier, Record};
use snarkvm_console_types::{Field, Group, U16};
use wasm_bindgen::prelude::*;

#[no_mangle]
#[wasm_bindgen]
pub fn decrypt_ciphertext(
    vk: &str,
    tpk: &str,
    program_name: &str,
    function_name: &str,
    index: u16,
    ciphertext: &str,
) -> Result<String, JsValue> {
    let vk = ViewKey::<Testnet3>::from_str(vk).map_err(|_| JsValue::from_str("Invalid view key"))?;
    let tpk = Group::<Testnet3>::from_str(tpk).map_err(|_| JsValue::from_str("Invalid transition public key"))?;
    let tvk = (tpk * *vk).to_x_coordinate();
    let function_id = <Testnet3 as Network>::hash_bhp1024(
        &(
            U16::<Testnet3>::new(3),
            &Identifier::<Testnet3>::from_str(program_name).map_err(|_| JsValue::from_str("Invalid program name"))?,
            &Identifier::<Testnet3>::from_str("aleo").unwrap(),
            &Identifier::<Testnet3>::from_str(function_name).map_err(|_| JsValue::from_str("Invalid function name"))?,
        )
            .to_bits_le(),
    )
    .unwrap();
    let ivk = <Testnet3 as Network>::hash_psd4(&[function_id, tvk, Field::from_u16(index)]).unwrap();
    let ciphertext = Ciphertext::<Testnet3>::from_str(ciphertext).unwrap();
    Ok(ciphertext
        .decrypt_symmetric(ivk)
        .map_err(|_| JsValue::from_str("Unable to decrypt ciphertext"))?
        .to_string())
}

#[wasm_bindgen(getter_with_clone)]
pub struct RecordData {
    pub string: String,
    plaintext: Vec<String>,
}

#[wasm_bindgen]
impl RecordData {
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> Box<[JsValue]> {
        self.plaintext
            .iter()
            .map(|s| JsValue::from_str(s))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }
}

#[no_mangle]
#[wasm_bindgen]
pub fn decrypt_record(vk: &str, record: &str) -> Result<RecordData, JsValue> {
    let vk = ViewKey::<Testnet3>::from_str(vk).map_err(|_| JsValue::from_str("Invalid view key"))?;
    let record =
        Record::<Testnet3, Ciphertext<Testnet3>>::from_str(record).map_err(|_| JsValue::from_str("Invalid record"))?;
    let decrypted_record = record
        .decrypt(&vk)
        .map_err(|_| JsValue::from_str("Unable to decrypt record"))?;
    let mut res = Vec::new();
    res.push(decrypted_record.owner().to_string());
    for (_, value) in decrypted_record.data() {
        res.push(value.to_string());
    }
    Ok(RecordData {
        string: decrypted_record.to_string(),
        plaintext: res,
    })
}
