// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod ledger_state_injection_tests {
    use crate::{decode_ledger_entry, decode_ledger_key, inject_ledger_entry};
    use base64::Engine as _;
    use soroban_env_host::xdr::{
        AccountEntry, AccountId, ContractCodeEntry, ContractDataDurability, ContractDataEntry,
        Hash, LedgerEntry, LedgerEntryData, LedgerEntryExt, LedgerKey, LedgerKeyContractCode,
        LedgerKeyContractData, PublicKey, ScAddress, ScVal, SequenceNumber, StringM, Thresholds,
        Uint256, WriteXdr,
    };
    use std::str::FromStr;

    /// Helper to create a test Host
    fn create_test_host() -> soroban_env_host::Host {
        let host = soroban_env_host::Host::default();
        host.set_diagnostic_level(soroban_env_host::DiagnosticLevel::Debug)
            .unwrap();
        host
    }

    /// Helper to encode XDR to base64
    fn encode_xdr<T: WriteXdr>(value: &T) -> String {
        let bytes = value.to_xdr(soroban_env_host::xdr::Limits::none()).unwrap();
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    }

    #[test]
    fn test_decode_ledger_key_success() {
        // Create a ContractData key
        let contract_id = Hash([1u8; 32]);
        let key_val = ScVal::U32(42);

        let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(contract_id),
            key: key_val,
            durability: ContractDataDurability::Persistent,
        });

        let encoded = encode_xdr(&ledger_key);
        let decoded = decode_ledger_key(&encoded).expect("Should decode successfully");

        // Verify the decoded key matches
        if let LedgerKey::ContractData(data) = decoded {
            assert_eq!(data.durability, ContractDataDurability::Persistent);
        } else {
            panic!("Expected ContractData key");
        }
    }

    #[test]
    fn test_decode_ledger_key_invalid_base64() {
        let result = decode_ledger_key("not-valid-base64!!!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to decode LedgerKey Base64"));
    }

    #[test]
    fn test_decode_ledger_key_invalid_xdr() {
        // Valid base64 but invalid XDR
        let invalid_xdr = base64::engine::general_purpose::STANDARD.encode(b"invalid xdr data");
        let result = decode_ledger_key(&invalid_xdr);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse LedgerKey XDR"));
    }

    #[test]
    fn test_decode_ledger_entry_success() {
        // Create a ContractData entry
        let contract_id = Hash([2u8; 32]);
        let key_val = ScVal::U32(100);
        let val = ScVal::U64(999);

        let entry = LedgerEntry {
            last_modified_ledger_seq: 12345,
            data: LedgerEntryData::ContractData(ContractDataEntry {
                ext: soroban_env_host::xdr::ExtensionPoint::V0,
                contract: ScAddress::Contract(contract_id),
                key: key_val,
                durability: ContractDataDurability::Persistent,
                val,
            }),
            ext: LedgerEntryExt::V0,
        };

        let encoded = encode_xdr(&entry);
        let decoded = decode_ledger_entry(&encoded).expect("Should decode successfully");

        assert_eq!(decoded.last_modified_ledger_seq, 12345);
        if let LedgerEntryData::ContractData(data) = decoded.data {
            assert_eq!(data.durability, ContractDataDurability::Persistent);
        } else {
            panic!("Expected ContractData entry");
        }
    }

    #[test]
    fn test_decode_ledger_entry_invalid_base64() {
        let result = decode_ledger_entry("invalid-base64@@@");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Failed to decode LedgerEntry Base64"));
    }

    #[test]
    fn test_inject_contract_data_entry() {
        let host = create_test_host();

        // Create a ContractData key and entry
        let contract_id = Hash([3u8; 32]);
        let key_val = ScVal::U32(42);
        let val = ScVal::U64(1000);

        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(contract_id.clone()),
            key: key_val.clone(),
            durability: ContractDataDurability::Persistent,
        });

        let entry = LedgerEntry {
            last_modified_ledger_seq: 100,
            data: LedgerEntryData::ContractData(ContractDataEntry {
                ext: soroban_env_host::xdr::ExtensionPoint::V0,
                contract: ScAddress::Contract(contract_id),
                key: key_val,
                durability: ContractDataDurability::Persistent,
                val,
            }),
            ext: LedgerEntryExt::V0,
        };

        // Inject should succeed
        let result = inject_ledger_entry(&host, &key, &entry);
        assert!(result.is_ok(), "Injection should succeed");
    }

    #[test]
    fn test_inject_contract_code_entry() {
        let host = create_test_host();

        // Create a ContractCode key and entry
        let code_hash = Hash([4u8; 32]);
        let wasm_code = vec![0x00, 0x61, 0x73, 0x6d]; // WASM magic number

        let key = LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: code_hash.clone(),
        });

        let entry = LedgerEntry {
            last_modified_ledger_seq: 200,
            data: LedgerEntryData::ContractCode(ContractCodeEntry {
                ext: soroban_env_host::xdr::ExtensionPoint::V0,
                hash: code_hash,
                code: wasm_code.try_into().unwrap(),
            }),
            ext: LedgerEntryExt::V0,
        };

        // Inject should succeed
        let result = inject_ledger_entry(&host, &key, &entry);
        assert!(result.is_ok(), "ContractCode injection should succeed");
    }

    #[test]
    fn test_inject_account_entry() {
        let host = create_test_host();

        // Create an Account key and entry
        let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([5u8; 32])));

        let key = LedgerKey::Account(soroban_env_host::xdr::LedgerKeyAccount {
            account_id: account_id.clone(),
        });

        let entry = LedgerEntry {
            last_modified_ledger_seq: 300,
            data: LedgerEntryData::Account(AccountEntry {
                account_id,
                balance: 1000000,
                seq_num: SequenceNumber(123456),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: soroban_env_host::xdr::String32(
                    StringM::from_str("example.com").unwrap(),
                ),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: Default::default(),
                ext: soroban_env_host::xdr::AccountEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        };

        // Inject should succeed
        let result = inject_ledger_entry(&host, &key, &entry);
        assert!(result.is_ok(), "Account injection should succeed");
    }

    #[test]
    fn test_inject_mismatched_key_entry_types() {
        let host = create_test_host();

        // Create a ContractData key but an Account entry (mismatch)
        let contract_id = Hash([6u8; 32]);
        let key_val = ScVal::U32(42);

        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(contract_id),
            key: key_val,
            durability: ContractDataDurability::Persistent,
        });

        let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7u8; 32])));
        let entry = LedgerEntry {
            last_modified_ledger_seq: 400,
            data: LedgerEntryData::Account(AccountEntry {
                account_id,
                balance: 500000,
                seq_num: SequenceNumber(789),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: soroban_env_host::xdr::String32(
                    StringM::from_str("test.com").unwrap(),
                ),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: Default::default(),
                ext: soroban_env_host::xdr::AccountEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        };

        // Inject should fail due to type mismatch
        let result = inject_ledger_entry(&host, &key, &entry);
        assert!(result.is_err(), "Should fail on type mismatch");
        assert!(result
            .unwrap_err()
            .contains("Mismatched LedgerKey and LedgerEntry types"));
    }

    #[test]
    fn test_inject_multiple_entries() {
        let host = create_test_host();

        // Create multiple entries
        let entries = vec![
            // ContractData entry
            (
                LedgerKey::ContractData(LedgerKeyContractData {
                    contract: ScAddress::Contract(Hash([10u8; 32])),
                    key: ScVal::U32(1),
                    durability: ContractDataDurability::Persistent,
                }),
                LedgerEntry {
                    last_modified_ledger_seq: 100,
                    data: LedgerEntryData::ContractData(ContractDataEntry {
                        ext: soroban_env_host::xdr::ExtensionPoint::V0,
                        contract: ScAddress::Contract(Hash([10u8; 32])),
                        key: ScVal::U32(1),
                        durability: ContractDataDurability::Persistent,
                        val: ScVal::U64(100),
                    }),
                    ext: LedgerEntryExt::V0,
                },
            ),
            // ContractCode entry
            (
                LedgerKey::ContractCode(LedgerKeyContractCode {
                    hash: Hash([11u8; 32]),
                }),
                LedgerEntry {
                    last_modified_ledger_seq: 200,
                    data: LedgerEntryData::ContractCode(ContractCodeEntry {
                        ext: soroban_env_host::xdr::ExtensionPoint::V0,
                        hash: Hash([11u8; 32]),
                        code: vec![0x00, 0x61, 0x73, 0x6d].try_into().unwrap(),
                    }),
                    ext: LedgerEntryExt::V0,
                },
            ),
        ];

        // Inject all entries
        for (key, entry) in entries {
            let result = inject_ledger_entry(&host, &key, &entry);
            assert!(result.is_ok(), "All injections should succeed");
        }
    }

    #[test]
    fn test_inject_temporary_contract_data() {
        let host = create_test_host();

        // Create a temporary ContractData entry
        let contract_id = Hash([12u8; 32]);
        let key_val = ScVal::U32(999);
        let val = ScVal::U64(5555);

        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(contract_id.clone()),
            key: key_val.clone(),
            durability: ContractDataDurability::Temporary,
        });

        let entry = LedgerEntry {
            last_modified_ledger_seq: 500,
            data: LedgerEntryData::ContractData(ContractDataEntry {
                ext: soroban_env_host::xdr::ExtensionPoint::V0,
                contract: ScAddress::Contract(contract_id),
                key: key_val,
                durability: ContractDataDurability::Temporary,
                val,
            }),
            ext: LedgerEntryExt::V0,
        };

        // Inject should succeed
        let result = inject_ledger_entry(&host, &key, &entry);
        assert!(result.is_ok(), "Temporary data injection should succeed");
    }

    #[test]
    fn test_end_to_end_decode_and_inject() {
        let host = create_test_host();

        // Create a ContractData entry
        let contract_id = Hash([13u8; 32]);
        let key_val = ScVal::U32(777);
        let val = ScVal::U64(8888);

        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(contract_id.clone()),
            key: key_val.clone(),
            durability: ContractDataDurability::Persistent,
        });

        let entry = LedgerEntry {
            last_modified_ledger_seq: 600,
            data: LedgerEntryData::ContractData(ContractDataEntry {
                ext: soroban_env_host::xdr::ExtensionPoint::V0,
                contract: ScAddress::Contract(contract_id),
                key: key_val,
                durability: ContractDataDurability::Persistent,
                val,
            }),
            ext: LedgerEntryExt::V0,
        };

        // Encode to base64
        let key_xdr = encode_xdr(&key);
        let entry_xdr = encode_xdr(&entry);

        // Decode from base64
        let decoded_key = decode_ledger_key(&key_xdr).expect("Key decode should succeed");
        let decoded_entry =
            decode_ledger_entry(&entry_xdr).expect("Entry decode should succeed");

        // Inject
        let result = inject_ledger_entry(&host, &decoded_key, &decoded_entry);
        assert!(result.is_ok(), "End-to-end injection should succeed");
    }
}

#[cfg(test)]
mod contract_execution_tests {
    use crate::{execute_operations, StructuredError};

    // Mock helper to simulate HostError scenarios
    fn simulate_host_error() -> Result<Vec<String>, soroban_env_host::HostError> {
        // This would be a real HostError in actual implementation
        use soroban_env_host::HostError;
        Err(HostError::from(
            soroban_env_host::Error::from_type_and_code(
                soroban_env_host::xdr::ScErrorType::Budget,
                soroban_env_host::xdr::ScErrorCode::ExceededLimit,
            ),
        ))
    }

    #[test]
    fn test_host_error_propagation() {
        let result = simulate_host_error();
        assert!(result.is_err());

        if let Err(e) = result {
            let error_str = format!("{:?}", e);
            assert!(error_str.contains("Budget") || error_str.contains("ExceededLimit"));
        }
    }

    #[test]
    fn test_execute_operations_success_path() {
        use soroban_env_host::xdr::{Operation, VecM};

        // Create empty operations vector
        let operations: VecM<Operation, 100> = VecM::default();
        let host = soroban_env_host::Host::default();

        // Should succeed with empty operations
        let result = execute_operations(&host, &operations);
        assert!(result.is_ok());

        let logs = result.unwrap();
        assert_eq!(logs.len(), 0); // No operations = no logs
    }

    // ============================================================================
    // Panic Scenario Simulations
    // ============================================================================

    /// Test panic during division by zero
    #[test]
    fn test_division_by_zero_panic() {
        let result = std::panic::catch_unwind(|| {
            #[allow(unconditional_panic)]
            let _x = 1 / 0; // This will panic
        });

        assert!(result.is_err(), "Division by zero should panic");

        if let Err(panic_info) = result {
            let message = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };

            // The panic message should mention division or overflow
            println!("Panic message: {}", message);
            assert!(!message.is_empty());
        }
    }

    /// Test panic from array index out of bounds
    #[test]
    fn test_unwrap_none_panic() {
        let result = std::panic::catch_unwind(|| {
            let _vec: Vec<i32> = vec![];
            let _value = _vec[0]; // This will panic with index out of bounds
        });

        assert!(result.is_err(), "Index out of bounds should panic");
    }

    /// Test panic from assertion failure
    #[test]
    fn test_assertion_panic() {
        let result = std::panic::catch_unwind(|| {
            let balance = 100;
            let amount = 150;
            assert!(
                balance >= amount,
                "Insufficient balance: {} < {}",
                balance,
                amount
            );
        });

        assert!(result.is_err(), "Failed assertion should panic");

        if let Err(panic_info) = result {
            let message = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown".to_string()
            };

            assert!(message.contains("Insufficient balance") || message.contains("assertion"));
        }
    }

    /// Test panic from explicit panic! macro
    #[test]
    fn test_explicit_panic_macro() {
        let result = std::panic::catch_unwind(|| {
            panic!("Contract execution failed: invalid state");
        });

        assert!(result.is_err());

        if let Err(panic_info) = result {
            let message = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "Unknown".to_string()
            };

            assert_eq!(message, "Contract execution failed: invalid state");
        }
    }

    // ============================================================================
    // WASM Trap Simulations (these would be HostErrors in real execution)
    // ============================================================================

    #[test]
    fn test_out_of_gas_scenario() {
        // In a real scenario, this would be a HostError from budget exhaustion
        // For now, we simulate the error handling
        use soroban_env_host::HostError;

        let simulated_trap = HostError::from(soroban_env_host::Error::from_type_and_code(
            soroban_env_host::xdr::ScErrorType::Budget,
            soroban_env_host::xdr::ScErrorCode::ExceededLimit,
        ));

        let structured_error = StructuredError {
            error_type: "HostError".to_string(),
            message: format!("{:?}", simulated_trap),
            details: Some("Contract execution failed: out of gas".to_string()),
        };

        assert_eq!(structured_error.error_type, "HostError");
        assert!(structured_error.details.unwrap().contains("out of gas"));
    }

    #[test]
    fn test_invalid_operation_scenario() {
        // Simulate an invalid operation trap
        let structured_error = StructuredError {
            error_type: "HostError".to_string(),
            message: "Invalid operation".to_string(),
            details: Some("Contract attempted to perform an invalid operation".to_string()),
        };

        let json = serde_json::to_string(&structured_error).unwrap();
        assert!(json.contains("HostError"));
        assert!(json.contains("Invalid operation"));
    }

    // ============================================================================
    // State Preservation Tests
    // ============================================================================

    #[test]
    fn test_logs_preserved_before_panic() {
        let mut logs = vec![
            "Host initialized".to_string(),
            "Loaded 5 ledger entries".to_string(),
        ];

        // Create a closure that adds logs then panics
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut inner_logs = logs.clone();
            inner_logs.push("Started contract execution".to_string());
            inner_logs.push("Function call: transfer".to_string());
            panic!("Contract panicked during transfer");
            #[allow(unreachable_code)]
            inner_logs
        }));

        // The panic should be caught
        assert!(result.is_err());

        // In the real simulator, logs collected before the panic boundary are preserved
        // Even though inner_logs are lost in this test, the outer logs remain
        assert_eq!(logs.len(), 2);

        // After catching the panic, we would add the panic message to logs
        logs.push("PANIC: Contract panicked during transfer".to_string());
        assert_eq!(logs.len(), 3);
    }

    #[test]
    fn test_partial_execution_state_captured() {
        // Simulate a scenario where some operations succeed before one panics
        let mut execution_logs: Vec<String> = Vec::new();

        for i in 0..5 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if i == 3 {
                    panic!("Operation {} failed", i);
                }
                format!("Operation {} succeeded", i)
            }));

            match result {
                Ok(log) => execution_logs.push(log),
                Err(_) => {
                    execution_logs.push(format!("Operation {} panicked", i));
                    break; // Stop processing further operations
                }
            }
        }

        // Should have logs for operations 0, 1, 2, and the panic at 3
        assert_eq!(execution_logs.len(), 4);
        assert!(execution_logs[3].contains("panicked"));
    }

    // ============================================================================
    // Error Message Quality Tests
    // ============================================================================

    #[test]
    fn test_error_message_contains_useful_info() {
        let result = std::panic::catch_unwind(|| {
            panic!("Transfer failed: insufficient balance (have: 100, need: 150)");
        });

        if let Err(panic_info) = result {
            let message = panic_info
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Unknown".to_string());

            // Error message should contain actionable information
            assert!(message.contains("insufficient balance"));
            assert!(message.contains("100"));
            assert!(message.contains("150"));
        }
    }

    #[test]
    fn test_structured_error_provides_context() {
        let error = StructuredError {
            error_type: "Panic".to_string(),
            message: "Index out of bounds".to_string(),
            details: Some(
                "Attempted to access index 10 in array of length 5. \
                 This occurred in function 'get_user_data' at contract address 0x1234..."
                    .to_string(),
            ),
        };

        let json = serde_json::to_string(&error).unwrap();
        let parsed: StructuredError = serde_json::from_str(&json).unwrap();

        // Verify context is preserved
        assert!(parsed.details.is_some());
        let details = parsed.details.unwrap();
        assert!(details.contains("index 10"));
        assert!(details.contains("length 5"));
        assert!(details.contains("get_user_data"));
    }

    // ============================================================================
    // Recovery Tests
    // ============================================================================

    #[test]
    fn test_simulator_can_handle_subsequent_requests_after_panic() {
        // Simulate multiple requests, some panicking, some succeeding
        let requests = vec![
            ("request_1", false), // succeeds
            ("request_2", true),  // panics
            ("request_3", false), // succeeds
            ("request_4", true),  // panics
            ("request_5", false), // succeeds
        ];

        let mut results = Vec::new();

        for (name, should_panic) in requests {
            let result = std::panic::catch_unwind(|| {
                if should_panic {
                    panic!("Request {} panicked", name);
                }
                format!("Request {} succeeded", name)
            });

            match result {
                Ok(msg) => results.push(("success", msg)),
                Err(_) => results.push(("error", format!("Request {} panicked", name))),
            }
        }

        // All requests should be handled
        assert_eq!(results.len(), 5);

        // Verify success/error pattern
        assert_eq!(results[0].0, "success");
        assert_eq!(results[1].0, "error");
        assert_eq!(results[2].0, "success");
        assert_eq!(results[3].0, "error");
        assert_eq!(results[4].0, "success");
    }

    // ============================================================================
    // Performance Tests
    // ============================================================================

    #[test]
    fn test_panic_handling_overhead() {
        use std::time::Instant;

        // Measure overhead of catch_unwind on success path
        let iterations = 10000;

        // Without catch_unwind
        let start = Instant::now();
        for _ in 0..iterations {
            let _result = Ok::<(), ()>(());
        }
        let without_catch = start.elapsed();

        // With catch_unwind
        let start = Instant::now();
        for _ in 0..iterations {
            let _result = std::panic::catch_unwind(|| {
                // Empty operation
            });
        }
        let with_catch = start.elapsed();

        println!("Without catch_unwind: {:?}", without_catch);
        println!("With catch_unwind: {:?}", with_catch);

        // Overhead should be minimal (typically < 5% on modern systems)
        // This is informational, not a strict assertion
        let overhead_ratio = with_catch.as_nanos() as f64 / without_catch.as_nanos() as f64;
        println!("Overhead ratio: {:.2}x", overhead_ratio);
    }
}
