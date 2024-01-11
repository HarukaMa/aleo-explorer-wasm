use indexmap::IndexMap;
use rand::rngs::ThreadRng;
use snarkvm_circuit_network::AleoV0;
use std::str::FromStr;

use snarkvm_circuit_environment::environment::Environment;
use snarkvm_circuit_environment::prelude::bail;
use snarkvm_circuit_environment::Ternary;
use snarkvm_console_account::{Group, PrivateKey, Signature};
use snarkvm_console_network::prelude::{Itertools, Uniform};
use snarkvm_console_network::{traits::ToBits, Network, Testnet3};
use snarkvm_console_program::{
    Entry, EntryType, Identifier, Literal, LiteralType, Owner, Plaintext, PlaintextType, Record, Request, ToBytes,
    ToFields, Value, ValueType,
};
use snarkvm_console_types::Address;
use snarkvm_synthesizer_process::{
    Assignments, CallStack, CallTrait, Process, RegisterTypes, Registers, RegistersCall, Stack,
};
use snarkvm_synthesizer_program::{
    Instruction, Operand, Program, RegistersLoadCircuit, RegistersSigner, RegistersSignerCircuit, RegistersStore,
    RegistersStoreCircuit,
};
use wasm_bindgen::prelude::*;

type N = Testnet3;
type A = AleoV0;

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

#[no_mangle]
#[wasm_bindgen]
pub fn estimate_deployment_fee(program: &str) -> Result<u64, JsValue> {
    let program = Program::<N>::from_str(program)
        .map_err(|e| JsValue::from_str(format!("failed to parse program: {e}").as_str()))?;
    let program_size = program
        .to_bytes_le()
        .map_err(|e| JsValue::from_str(format!("failed to serialize program: {e}").as_str()))?
        .len() as u64;
    let functions = program.functions();
    let identifier_size: u64 = functions
        .iter()
        .map(|(identifier, _)| identifier.to_string().len() as u64)
        .sum();
    let namespace_cost = 10u64.pow(10u32.saturating_sub(program.id().name().to_string().len() as u32)) * 1000000;
    return Ok(1000 * (program_size + identifier_size + functions.len() as u64 * 724 + 5) + namespace_cost);
}

#[wasm_bindgen(getter_with_clone)]
pub struct FunctionConstraintNumber {
    pub function_name: String,
    pub constraint_number: u64,
}

// almost verbatim copy from snarkvm stack

fn sample_plaintext_internal(
    program: &Program<N>,
    plaintext_type: &PlaintextType<N>,
    depth: usize,
    rng: &mut ThreadRng,
) -> Result<Plaintext<N>, &'static str> {
    // Sample the plaintext value.
    let plaintext = match plaintext_type {
        // Sample a literal.
        PlaintextType::Literal(literal_type) => {
            Plaintext::Literal(Literal::sample(*literal_type, rng), Default::default())
        }
        // Sample a struct.
        PlaintextType::Struct(struct_name) => {
            // Retrieve the struct.
            let struct_ = program
                .get_struct(struct_name)
                .map_err(|_| "Failed to retrieve struct")?;
            // Sample each member of the struct.
            let members = struct_
                .members()
                .iter()
                .map(|(member_name, member_type)| {
                    // Sample the member value.
                    let member = sample_plaintext_internal(program, member_type, depth + 1, rng)?;
                    // Return the member.
                    Ok((*member_name, member))
                })
                .collect::<Result<IndexMap<_, _>, &'static str>>()?;

            Plaintext::Struct(members, Default::default())
        }
        // Sample an array.
        PlaintextType::Array(array_type) => {
            // Sample each element of the array.
            let elements = (0..**array_type.length())
                .map(|_| {
                    // Sample the element value.
                    sample_plaintext_internal(program, array_type.next_element_type(), depth + 1, rng)
                })
                .collect::<Result<Vec<_>, &'static str>>()?;

            Plaintext::Array(elements, Default::default())
        }
    };
    // Return the plaintext.
    Ok(plaintext)
}

fn sample_plaintext(
    program: &Program<N>,
    plaintext_type: &PlaintextType<N>,
    rng: &mut ThreadRng,
) -> Result<Plaintext<N>, &'static str> {
    // Sample a plaintext value.
    let plaintext = sample_plaintext_internal(program, plaintext_type, 0, rng)?;
    // Return the plaintext value.
    Ok(plaintext)
}

fn sample_entry_internal(
    program: &Program<N>,
    entry_type: &EntryType<N>,
    depth: usize,
    rng: &mut ThreadRng,
) -> Result<Entry<N, Plaintext<N>>, &'static str> {
    match entry_type {
        EntryType::Constant(plaintext_type)
        | EntryType::Public(plaintext_type)
        | EntryType::Private(plaintext_type) => {
            // Sample the plaintext value.
            let plaintext = sample_plaintext_internal(program, plaintext_type, depth, rng)?;
            // Return the entry.
            match entry_type {
                EntryType::Constant(..) => Ok(Entry::Constant(plaintext)),
                EntryType::Public(..) => Ok(Entry::Public(plaintext)),
                EntryType::Private(..) => Ok(Entry::Private(plaintext)),
            }
        }
    }
}

fn sample_record_internal(
    program: &Program<N>,
    burner_address: &Address<N>,
    record_name: &Identifier<N>,
    depth: usize,
    rng: &mut ThreadRng,
) -> Result<Record<N, Plaintext<N>>, &'static str> {
    // Retrieve the record type from the program.
    let record_type = program
        .get_record(record_name)
        .map_err(|_| "Failed to retrieve record type")?;

    // Initialize the owner based on the visibility.
    let owner = match record_type.owner().is_public() {
        true => Owner::Public(*burner_address),
        false => Owner::Private(Plaintext::Literal(
            Literal::Address(*burner_address),
            Default::default(),
        )),
    };

    // Initialize the record data according to the defined type.
    let data = record_type
        .entries()
        .iter()
        .map(|(entry_name, entry_type)| {
            // Sample the entry value.
            let entry = sample_entry_internal(program, entry_type, depth + 1, rng)?;
            // Return the entry.
            Ok((*entry_name, entry))
        })
        .collect::<Result<IndexMap<_, _>, &'static str>>()?;

    // Initialize the nonce.
    let nonce = Group::rand(rng);

    // Return the record.
    Record::<N, Plaintext<N>>::from_plaintext(owner, data, nonce).map_err(|_| "Failed to create record")
}

fn sample_record(
    program: &Program<N>,
    burner_address: &Address<N>,
    record_name: &Identifier<N>,
    rng: &mut ThreadRng,
) -> Result<Record<N, Plaintext<N>>, &'static str> {
    // Sample a record.
    let record = sample_record_internal(program, burner_address, record_name, 0, rng)?;
    // Return the record.
    Ok(record)
}

fn sample_value(
    program: &Program<N>,
    burner_address: &Address<N>,
    value_type: &ValueType<N>,
    rng: &mut ThreadRng,
) -> Result<Value<N>, &'static str> {
    match value_type {
        ValueType::Constant(plaintext_type)
        | ValueType::Public(plaintext_type)
        | ValueType::Private(plaintext_type) => Ok(Value::Plaintext(sample_plaintext(program, plaintext_type, rng)?)),
        ValueType::Record(record_name) => Ok(Value::Record(sample_record(program, burner_address, record_name, rng)?)),
        ValueType::ExternalRecord(_) => {
            Err("Illegal operation: Cannot sample external records (for '{locator}.record').")
        }
        ValueType::Future(_) => Err("Illegal operation: Cannot sample futures (for '{locator}.future')."),
    }
}

fn execute_function(
    stack: &Stack<N>,
    program: &Program<N>,
    mut call_stack: CallStack<N>,
    rng: &mut ThreadRng,
) -> Result<u64, &'static str> {
    AleoV0::reset();

    let console_request = call_stack.pop().map_err(|_| "Call stack empty")?;

    let console_is_root = true;
    let console_parent = console_request
        .program_id()
        .to_address()
        .map_err(|_| "Invalid program ID")?;

    let function = program
        .get_function(console_request.function_name())
        .map_err(|_| "Invalid function name")?;
    // Retrieve the number of inputs.
    let num_inputs = function.inputs().len();
    // Retrieve the input types.
    let input_types = function.input_types();
    // Retrieve the output types.
    let output_types = function.output_types();

    let mut registers = Registers::new(
        call_stack,
        RegisterTypes::from_function(stack, &function).map_err(|_| "Failed to setup registers")?,
    );

    use snarkvm_circuit_environment::{Eject, Inject};

    // Inject the transition public key `tpk` as `Mode::Public`.
    let tpk =
        snarkvm_circuit_types::Group::<A>::new(snarkvm_circuit_environment::Mode::Public, console_request.to_tpk());
    // Inject the request as `Mode::Private`.
    let request =
        snarkvm_circuit_program::Request::new(snarkvm_circuit_environment::Mode::Private, console_request.clone());

    // Inject `is_root` as `Mode::Public`.
    let is_root = snarkvm_circuit_types::Boolean::new(snarkvm_circuit_environment::Mode::Public, console_is_root);
    // Inject the parent as `Mode::Public`.
    let parent = snarkvm_circuit_types::Address::new(snarkvm_circuit_environment::Mode::Public, console_parent);
    // Determine the caller.
    let caller = Ternary::ternary(&is_root, request.signer(), &parent);

    A::assert(request.verify(&input_types, &tpk));

    // Set the transition signer.
    registers.set_signer(*console_request.signer());
    // Set the transition signer, as a circuit.
    registers.set_signer_circuit(request.signer().clone());

    // Set the transition caller.
    registers.set_caller(caller.eject_value());
    // Set the transition caller, as a circuit.
    registers.set_caller_circuit(caller);

    // Set the transition view key.
    registers.set_tvk(*console_request.tvk());
    // Set the transition view key, as a circuit.
    registers.set_tvk_circuit(request.tvk().clone());

    function
        .inputs()
        .iter()
        .map(|i| i.register())
        .zip_eq(request.inputs())
        .try_for_each(|(register, input)| {
            // If the circuit is in execute mode, then store the console input.
            if let CallStack::Execute(..) = registers.call_stack() {
                // Assign the console input to the register.
                registers.store(stack, register, input.eject_value())?;
            }
            // Assign the circuit input to the register.
            registers.store_circuit(stack, register, input.clone())
        })
        .map_err(|_| "Failed to store inputs")?;

    let mut contains_function_call = false;

    // Execute the instructions.
    for instruction in function.instructions() {
        // If the circuit is in execute mode, then evaluate the instructions.
        if let CallStack::Execute(..) = registers.call_stack() {
            // Evaluate the instruction.
            let result = match instruction {
                // If the instruction is a `call` instruction, we need to handle it separately.
                Instruction::Call(call) => CallTrait::evaluate(call, stack, &mut registers),
                // Otherwise, evaluate the instruction normally.
                _ => instruction.evaluate(stack, &mut registers),
            };
            // If the evaluation fails, bail and return the error.
            if let Err(error) = result {
                return Err("Failed to evaluate instruction");
            }
        }

        // Execute the instruction.
        let result = match instruction {
            // If the instruction is a `call` instruction, we need to handle it separately.
            Instruction::Call(call) => CallTrait::execute(call, stack, &mut registers, rng),
            // Otherwise, execute the instruction normally.
            _ => instruction.execute(stack, &mut registers),
        };
        // If the execution fails, bail and return the error.
        if let Err(error) = result {
            return Err("Failed to execute instruction");
        }

        // If the instruction was a function call, then set the tracker to `true`.
        if let Instruction::Call(call) = instruction {
            // Check if the call is a function call.
            if call
                .is_function_call(stack)
                .map_err(|_| "Failed to check if call is a function call")?
            {
                contains_function_call = true;
            }
        }
    }
    let output_operands = &function
        .outputs()
        .iter()
        .map(|output| output.operand())
        .collect::<Vec<_>>();
    let outputs = output_operands
        .iter()
        .map(|operand| {
            match operand {
                // If the operand is a literal, use the literal directly.
                Operand::Literal(literal) => Ok(snarkvm_circuit_program::Value::Plaintext(
                    snarkvm_circuit_program::Plaintext::from(snarkvm_circuit_program::Literal::new(
                        snarkvm_circuit_environment::Mode::Constant,
                        literal.clone(),
                    )),
                )),
                // If the operand is a register, retrieve the stack value from the register.
                Operand::Register(register) => registers.load_circuit(stack, &Operand::Register(register.clone())),
                // If the operand is the program ID, convert the program ID into an address.
                Operand::ProgramID(program_id) => Ok(snarkvm_circuit_program::Value::Plaintext(
                    snarkvm_circuit_program::Plaintext::from(snarkvm_circuit_program::Literal::Address(
                        snarkvm_circuit_types::Address::new(
                            snarkvm_circuit_environment::Mode::Constant,
                            program_id.to_address()?,
                        ),
                    )),
                )),
                // If the operand is the signer, retrieve the signer from the registers.
                Operand::Signer => Ok(snarkvm_circuit_program::Value::Plaintext(
                    snarkvm_circuit_program::Plaintext::from(snarkvm_circuit_program::Literal::Address(
                        registers.signer_circuit()?,
                    )),
                )),
                // If the operand is the caller, retrieve the caller from the registers.
                Operand::Caller => Ok(snarkvm_circuit_program::Value::Plaintext(
                    snarkvm_circuit_program::Plaintext::from(snarkvm_circuit_program::Literal::Address(
                        registers.caller_circuit()?,
                    )),
                )),
                // If the operand is the block height, throw an error.
                Operand::BlockHeight => {
                    bail!("Illegal operation: cannot retrieve the block height in a function scope")
                }
            }
        })
        .collect::<Result<Vec<_>, snarkvm_console_account::Error>>()
        .map_err(|_| "Failed to retrieve outputs")?;

    let output_registers = output_operands
        .iter()
        .map(|operand| match operand {
            Operand::Register(register) => Some(register.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();

    snarkvm_circuit_program::Response::from_outputs(
        request.network_id(),
        request.program_id(),
        request.function_name(),
        num_inputs,
        request.tvk(),
        request.tcm(),
        outputs,
        &output_types,
        &output_registers,
    );
    let assignment = A::eject_assignment_and_reset();

    Ok(assignment.num_constraints())
}

#[wasm_bindgen]
pub fn worker_get_constraint_numbers(program: &str) -> Result<Vec<FunctionConstraintNumber>, JsValue> {
    let program = Program::<N>::from_str(program)
        .map_err(|e| JsValue::from_str(format!("failed to parse program: {e}").as_str()))?;
    let mut res = Vec::new();
    let mut rng = rand::thread_rng();
    let burner_private_key = PrivateKey::new(&mut rng).map_err(|e| JsValue::from_str(&*e.to_string()))?;

    let process = Process::load_web().map_err(|_| "Failed to setup process")?;
    let stack = Stack::new(&process, &program).map_err(|e| {
        web_sys::console::log_1(&JsValue::from_str(format!("Failed to setup stack: {e}").as_str()));
        "Failed to setup stack"
    })?;

    for function in program.functions().values() {
        web_sys::console::log_1(&format!("function name: {}", function.name()).into());
        // Compute the burner address.
        let burner_address = Address::try_from(&burner_private_key).map_err(|e| JsValue::from_str(&*e.to_string()))?;
        // Retrieve the input types.
        let input_types = function.input_types();
        // Sample the inputs.
        let inputs = input_types
            .iter()
            .map(|input_type| match input_type {
                ValueType::ExternalRecord(locator) => {
                    return Err(JsValue::from_str(
                        "Sorry, programs with external records are not supported yet",
                    ))
                }
                _ => sample_value(&program, &burner_address, input_type, &mut rng)
                    .map_err(|e| JsValue::from_str(&*e.to_string())),
            })
            .collect::<Result<Vec<_>, JsValue>>()?;

        // Compute the request, with a burner private key.
        let request = Request::sign(
            &burner_private_key,
            *program.id(),
            *function.name(),
            inputs.into_iter(),
            &input_types,
            &mut rng,
        )
        .map_err(|e| JsValue::from_str(format!("failed to sign request: {e}").as_str()))?;
        // Initialize the assignments.
        let assignments = Assignments::<N>::default();
        // Initialize the call stack.
        let call_stack = CallStack::CheckDeployment(vec![request], burner_private_key, assignments.clone());
        let constraints = execute_function(&stack, &program, call_stack, &mut rng)?;
        res.push(FunctionConstraintNumber {
            function_name: function.name().to_string(),
            constraint_number: constraints,
        });
    }
    Ok(res)
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
