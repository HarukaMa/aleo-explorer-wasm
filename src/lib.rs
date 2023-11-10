use std::str::FromStr;

use snarkvm_console_account::{Signature, ViewKey};
use snarkvm_console_network::{traits::ToBits, Network, Testnet3};
use snarkvm_console_program::{
    Ciphertext,
    FromBytes,
    Identifier,
    Literal,
    LiteralType,
    Plaintext,
    Record,
    ToBytes,
    ToFields,
    Value,
};
use snarkvm_console_types::{Address, Field, Group, U16};
use wasm_bindgen::prelude::*;

type N = Testnet3;

#[no_mangle]
#[wasm_bindgen]
pub fn hash_value(hash_type: &str, value: &str, destination_type: &str) -> Result<String, JsValue> {
    let destination_type = match destination_type {
        "address" => LiteralType::Address,
        "boolean" => LiteralType::Boolean,
        "field" => LiteralType::Field,
        "group" => LiteralType::Group,
        "i8" => LiteralType::I8,
        "i16" => LiteralType::I16,
        "i32" => LiteralType::I32,
        "i64" => LiteralType::I64,
        "i128" => LiteralType::I128,
        "u8" => LiteralType::U8,
        "u16" => LiteralType::U16,
        "u32" => LiteralType::U32,
        "u64" => LiteralType::U64,
        "u128" => LiteralType::U128,
        "scalar" => LiteralType::Scalar,
        "signature" => LiteralType::Signature,
        "string" => LiteralType::String,
        _ => {
            return Err(JsValue::from_str(
                format!("invalid destination type: {destination_type}").as_str(),
            ));
        }
    };
    let value = Value::Plaintext(
        Plaintext::from_str(value).map_err(|e| JsValue::from_str(format!("invalid input: {e}").as_str()))?,
    );
    let output = if hash_type.starts_with("psd") {
        let value_field = value
            .to_fields()
            .map_err(|e| JsValue::from_str(format!("invalid input: {e}").as_str()))?;
        match destination_type {
            LiteralType::Group | LiteralType::Address => Literal::Group(
                match hash_type {
                    "psd2" => N::hash_to_group_psd2(&value_field),
                    "psd4" => N::hash_to_group_psd4(&value_field),
                    "psd8" => N::hash_to_group_psd8(&value_field),
                    _ => return Err(JsValue::from_str(format!("invalid hash type: {hash_type}").as_str())),
                }
                .map_err(|e| JsValue::from_str(format!("failed to hash: {e}").as_str()))?,
            ),
            _ => Literal::Field(
                match hash_type {
                    "psd2" => N::hash_psd2(&value_field),
                    "psd4" => N::hash_psd4(&value_field),
                    "psd8" => N::hash_psd8(&value_field),
                    _ => return Err(JsValue::from_str(format!("invalid hash type: {hash_type}").as_str())),
                }
                .map_err(|e| JsValue::from_str(format!("failed to hash: {e}").as_str()))?,
            ),
        }
    } else {
        let value_bits = value.to_bits_le();
        Literal::Group(
            match hash_type {
                "bhp256" => N::hash_to_group_bhp256(&value_bits),
                "bhp512" => N::hash_to_group_bhp512(&value_bits),
                "bhp768" => N::hash_to_group_bhp768(&value_bits),
                "bhp1024" => N::hash_to_group_bhp1024(&value_bits),
                "ped64" => N::hash_to_group_ped64(&value_bits),
                "ped128" => N::hash_to_group_ped128(&value_bits),
                "keccak256" => N::hash_to_group_bhp256(
                    &N::hash_keccak256(&value_bits)
                        .map_err(|e| JsValue::from_str(format!("failed to hash: {e}").as_str()))?,
                ),
                "keccak384" => N::hash_to_group_bhp512(
                    &N::hash_keccak384(&value_bits)
                        .map_err(|e| JsValue::from_str(format!("failed to hash: {e}").as_str()))?,
                ),
                "keccak512" => N::hash_to_group_bhp512(
                    &N::hash_keccak512(&value_bits)
                        .map_err(|e| JsValue::from_str(format!("failed to hash: {e}").as_str()))?,
                ),
                "sha3_256" => N::hash_to_group_bhp256(
                    &N::hash_sha3_256(&value_bits)
                        .map_err(|e| JsValue::from_str(format!("failed to hash: {e}").as_str()))?,
                ),
                "sha3_384" => N::hash_to_group_bhp512(
                    &N::hash_sha3_384(&value_bits)
                        .map_err(|e| JsValue::from_str(format!("failed to hash: {e}").as_str()))?,
                ),
                "sha3_512" => N::hash_to_group_bhp512(
                    &N::hash_sha3_512(&value_bits)
                        .map_err(|e| JsValue::from_str(format!("failed to hash: {e}").as_str()))?,
                ),
                _ => return Err(JsValue::from_str(format!("invalid hash type: {hash_type}").as_str())),
            }
            .map_err(|e| JsValue::from_str(format!("failed to hash: {e}").as_str()))?,
        )
    };

    let output = output
        .cast_lossy(destination_type)
        .map_err(|e| JsValue::from_str(format!("failed to cast: {e}").as_str()))?;
    Ok(output.to_string())
}

#[no_mangle]
#[wasm_bindgen]
pub fn verify_signature(signature: &str, address: &str, message: &str, message_type: &str) -> Result<bool, JsValue> {
    let signature = Signature::<N>::from_str(signature)
        .map_err(|e| JsValue::from_str(format!("invalid signature: {e}").as_str()))?;
    let address =
        Address::<N>::from_str(address).map_err(|e| JsValue::from_str(format!("invalid address: {e}").as_str()))?;
    match message_type {
        "value" => {
            let message = Value::<N>::Plaintext(
                Plaintext::from_str(message)
                    .map_err(|e| JsValue::from_str(format!("invalid message: {e}").as_str()))?,
            )
            .to_fields()
            .map_err(|e| JsValue::from_str(format!("invalid message: {e}").as_str()))?;
            Ok(signature.verify(&address, &message))
        }
        "hex" => {
            let message =
                hex::decode(message).map_err(|e| JsValue::from_str(format!("invalid message: {e}").as_str()))?;
            Ok(signature.verify_bytes(&address, &message))
        }
        _ => Err(JsValue::from_str(
            format!("invalid message type: {message_type}").as_str(),
        )),
    }
}

#[no_mangle]
#[wasm_bindgen]
pub fn value_to_bytes(message: &str) -> Result<Box<[u8]>, JsValue> {
    let message = Value::<N>::Plaintext(
        Plaintext::from_str(message).map_err(|e| JsValue::from_str(format!("invalid message: {e}").as_str()))?,
    );
    Ok(message
        .to_bytes_le()
        .map_err(|e| JsValue::from_str(format!("invalid message: {e}").as_str()))?
        .into())
}

// #[no_mangle]
// #[wasm_bindgen]
// pub fn decrypt_ciphertext(
//     vk: &str,
//     tpk: &str,
//     program_name: &str,
//     function_name: &str,
//     index: u16,
//     ciphertext: &str,
// ) -> Result<String, JsValue> {
//     let vk = ViewKey::<Testnet3>::from_str(vk).map_err(|_| JsValue::from_str("Invalid view key"))?;
//     let tpk = Group::<Testnet3>::from_str(tpk).map_err(|_| JsValue::from_str("Invalid transition public key"))?;
//     let tvk = (tpk * *vk).to_x_coordinate();
//     let function_id = <Testnet3 as Network>::hash_bhp1024(
//         &(
//             U16::<Testnet3>::new(3),
//             &Identifier::<Testnet3>::from_str(program_name).map_err(|_| JsValue::from_str("Invalid program name"))?,
//             &Identifier::<Testnet3>::from_str("aleo").unwrap(),
//             &Identifier::<Testnet3>::from_str(function_name).map_err(|_| JsValue::from_str("Invalid function name"))?,
//         )
//             .to_bits_le(),
//     )
//     .unwrap();
//     let ivk = <Testnet3 as Network>::hash_psd4(&[function_id, tvk, Field::from_u16(index)]).unwrap();
//     let ciphertext = Ciphertext::<Testnet3>::from_str(ciphertext).unwrap();
//     Ok(ciphertext
//         .decrypt_symmetric(ivk)
//         .map_err(|_| JsValue::from_str("Unable to decrypt ciphertext"))?
//         .to_string())
// }
//
// #[wasm_bindgen(getter_with_clone)]
// pub struct RecordData {
//     pub string: String,
//     plaintext: Vec<String>,
// }
//
// #[wasm_bindgen]
// impl RecordData {
//     #[wasm_bindgen(getter)]
//     pub fn plaintext(&self) -> Box<[JsValue]> {
//         self.plaintext
//             .iter()
//             .map(|s| JsValue::from_str(s))
//             .collect::<Vec<_>>()
//             .into_boxed_slice()
//     }
// }
//
// #[no_mangle]
// #[wasm_bindgen]
// pub fn decrypt_record(vk: &str, record: &str) -> Result<RecordData, JsValue> {
//     let vk = ViewKey::<Testnet3>::from_str(vk).map_err(|_| JsValue::from_str("Invalid view key"))?;
//     let record =
//         Record::<Testnet3, Ciphertext<Testnet3>>::from_str(record).map_err(|_| JsValue::from_str("Invalid record"))?;
//     let decrypted_record = record
//         .decrypt(&vk)
//         .map_err(|_| JsValue::from_str("Unable to decrypt record"))?;
//     let mut res = Vec::new();
//     res.push(decrypted_record.owner().to_string());
//     for (_, value) in decrypted_record.data() {
//         res.push(value.to_string());
//     }
//     Ok(RecordData {
//         string: decrypted_record.to_string(),
//         plaintext: res,
//     })
// }
