use snarkvm_console_account::ViewKey;
use snarkvm_console_network::{traits::ToBits, Network, Testnet3};
use snarkvm_console_program::{Ciphertext, Identifier};
use snarkvm_console_types::{Field, Group, U16};
use std::str::FromStr;

#[no_mangle]
extern "C" fn decrypt_ciphertext() {
    let vk = ViewKey::<Testnet3>::from_str("AViewKey1your_key_here").unwrap();
    let tpk = Group::<Testnet3>::from_str("tpk_from_transition").unwrap();
    let tvk = (tpk * *vk).to_x_coordinate();
    let function_id = <Testnet3 as Network>::hash_bhp1024(
        &(
            U16::<Testnet3>::new(3),
            &Identifier::<Testnet3>::from_str("program_name").unwrap(),
            &Identifier::<Testnet3>::from_str("aleo").unwrap(),
            &Identifier::<Testnet3>::from_str("function_name").unwrap(),
        )
            .to_bits_le(),
    )
    .unwrap();
    let ivk = <Testnet3 as Network>::hash_psd4(&[function_id, tvk, Field::from_u16(1)]).unwrap();
    let ciphertext = Ciphertext::<Testnet3>::from_str("ciphertext1ciphertext_here").unwrap();
    println!("{:?}", ciphertext.decrypt_symmetric(ivk).unwrap());
}
