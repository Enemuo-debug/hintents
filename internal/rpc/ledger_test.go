// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"encoding/base64"
	"testing"

	"github.com/stellar/go/xdr"
)

func TestEncodeLedgerKey(t *testing.T) {
	// Create a test account key
	accountID := xdr.MustAddress("GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H")
	key := xdr.LedgerKey{
		Type: xdr.LedgerEntryTypeAccount,
		Account: &xdr.LedgerKeyAccount{
			AccountId: accountID,
		},
	}

	encoded, err := EncodeLedgerKey(key)
	if err != nil {
		t.Fatalf("Failed to encode ledger key: %v", err)
	}

	// Verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Encoded key is not valid base64: %v", err)
	}

	// Verify we can decode it back
	var decodedKey xdr.LedgerKey
	if err := decodedKey.UnmarshalBinary(decoded); err != nil {
		t.Fatalf("Failed to unmarshal decoded key: %v", err)
	}

	if decodedKey.Type != xdr.LedgerEntryTypeAccount {
		t.Errorf("Expected Account type, got %v", decodedKey.Type)
	}
}

func TestEncodeLedgerEntry(t *testing.T) {
	// Create a test account entry
	accountID := xdr.MustAddress("GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H")
	entry := xdr.LedgerEntry{
		LastModifiedLedgerSeq: 12345,
		Data: xdr.LedgerEntryData{
			Type: xdr.LedgerEntryTypeAccount,
			Account: &xdr.AccountEntry{
				AccountId: accountID,
				Balance:   1000000,
				SeqNum:    xdr.SequenceNumber(100),
			},
		},
	}

	encoded, err := EncodeLedgerEntry(entry)
	if err != nil {
		t.Fatalf("Failed to encode ledger entry: %v", err)
	}

	// Verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Encoded entry is not valid base64: %v", err)
	}

	// Verify we can decode it back
	var decodedEntry xdr.LedgerEntry
	if err := decodedEntry.UnmarshalBinary(decoded); err != nil {
		t.Fatalf("Failed to unmarshal decoded entry: %v", err)
	}

	if decodedEntry.Data.Type != xdr.LedgerEntryTypeAccount {
		t.Errorf("Expected Account type, got %v", decodedEntry.Data.Type)
	}

	if decodedEntry.Data.Account.Balance != 1000000 {
		t.Errorf("Expected balance 1000000, got %d", decodedEntry.Data.Account.Balance)
	}
}

func TestLedgerKeyFromEntry_Account(t *testing.T) {
	accountID := xdr.MustAddress("GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H")
	entry := xdr.LedgerEntry{
		Data: xdr.LedgerEntryData{
			Type: xdr.LedgerEntryTypeAccount,
			Account: &xdr.AccountEntry{
				AccountId: accountID,
				Balance:   1000000,
			},
		},
	}

	key := ledgerKeyFromEntry(entry)
	if key == nil {
		t.Fatal("Expected non-nil key")
	}

	if key.Type != xdr.LedgerEntryTypeAccount {
		t.Errorf("Expected Account type, got %v", key.Type)
	}

	if key.Account == nil {
		t.Fatal("Expected non-nil Account key")
	}

	if key.Account.AccountId.Address() != accountID.Address() {
		t.Errorf("Account ID mismatch")
	}
}

func TestLedgerKeyFromEntry_ContractData(t *testing.T) {
	contractID := xdr.Hash([32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	keyVal := xdr.ScVal{Type: xdr.ScValTypeScvU32, U32: xdr.Uint32Ptr(42)}

	entry := xdr.LedgerEntry{
		Data: xdr.LedgerEntryData{
			Type: xdr.LedgerEntryTypeContractData,
			ContractData: &xdr.ContractDataEntry{
				Contract:   xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &contractID},
				Key:        keyVal,
				Durability: xdr.ContractDataDurabilityPersistent,
				Val:        xdr.ScVal{Type: xdr.ScValTypeScvU64, U64: xdr.Uint64Ptr(1000)},
			},
		},
	}

	key := ledgerKeyFromEntry(entry)
	if key == nil {
		t.Fatal("Expected non-nil key")
	}

	if key.Type != xdr.LedgerEntryTypeContractData {
		t.Errorf("Expected ContractData type, got %v", key.Type)
	}

	if key.ContractData == nil {
		t.Fatal("Expected non-nil ContractData key")
	}

	if key.ContractData.Durability != xdr.ContractDataDurabilityPersistent {
		t.Errorf("Expected Persistent durability, got %v", key.ContractData.Durability)
	}
}

func TestLedgerKeyFromEntry_ContractCode(t *testing.T) {
	codeHash := xdr.Hash([32]byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200, 210, 220, 230, 240, 250, 255, 254, 253, 252, 251, 250, 249})

	entry := xdr.LedgerEntry{
		Data: xdr.LedgerEntryData{
			Type: xdr.LedgerEntryTypeContractCode,
			ContractCode: &xdr.ContractCodeEntry{
				Hash: codeHash,
				Code: []byte{0x00, 0x61, 0x73, 0x6d}, // WASM magic
			},
		},
	}

	key := ledgerKeyFromEntry(entry)
	if key == nil {
		t.Fatal("Expected non-nil key")
	}

	if key.Type != xdr.LedgerEntryTypeContractCode {
		t.Errorf("Expected ContractCode type, got %v", key.Type)
	}

	if key.ContractCode == nil {
		t.Fatal("Expected non-nil ContractCode key")
	}

	if key.ContractCode.Hash != codeHash {
		t.Errorf("Hash mismatch")
	}
}

func TestExtractFromChanges(t *testing.T) {
	accountID := xdr.MustAddress("GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H")
	entry := xdr.LedgerEntry{
		LastModifiedLedgerSeq: 100,
		Data: xdr.LedgerEntryData{
			Type: xdr.LedgerEntryTypeAccount,
			Account: &xdr.AccountEntry{
				AccountId: accountID,
				Balance:   5000000,
			},
		},
	}

	changes := xdr.LedgerEntryChanges{
		{
			Type:    xdr.LedgerEntryChangeTypeLedgerEntryCreated,
			Created: &entry,
		},
	}

	entries := make(map[string]string)
	extractFromChanges(changes, entries)

	if len(entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(entries))
	}

	// Verify we can decode the entry
	for keyXDR, entryXDR := range entries {
		// Decode key
		keyBytes, err := base64.StdEncoding.DecodeString(keyXDR)
		if err != nil {
			t.Fatalf("Failed to decode key: %v", err)
		}

		var key xdr.LedgerKey
		if err := key.UnmarshalBinary(keyBytes); err != nil {
			t.Fatalf("Failed to unmarshal key: %v", err)
		}

		if key.Type != xdr.LedgerEntryTypeAccount {
			t.Errorf("Expected Account type, got %v", key.Type)
		}

		// Decode entry
		entryBytes, err := base64.StdEncoding.DecodeString(entryXDR)
		if err != nil {
			t.Fatalf("Failed to decode entry: %v", err)
		}

		var decodedEntry xdr.LedgerEntry
		if err := decodedEntry.UnmarshalBinary(entryBytes); err != nil {
			t.Fatalf("Failed to unmarshal entry: %v", err)
		}

		if decodedEntry.Data.Account.Balance != 5000000 {
			t.Errorf("Expected balance 5000000, got %d", decodedEntry.Data.Account.Balance)
		}
	}
}

func TestExtractFromChanges_MultipleTypes(t *testing.T) {
	accountID := xdr.MustAddress("GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H")
	
	accountEntry := xdr.LedgerEntry{
		Data: xdr.LedgerEntryData{
			Type: xdr.LedgerEntryTypeAccount,
			Account: &xdr.AccountEntry{
				AccountId: accountID,
				Balance:   1000000,
			},
		},
	}

	contractID := xdr.Hash([32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	contractEntry := xdr.LedgerEntry{
		Data: xdr.LedgerEntryData{
			Type: xdr.LedgerEntryTypeContractData,
			ContractData: &xdr.ContractDataEntry{
				Contract:   xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &contractID},
				Key:        xdr.ScVal{Type: xdr.ScValTypeScvU32, U32: xdr.Uint32Ptr(100)},
				Durability: xdr.ContractDataDurabilityPersistent,
				Val:        xdr.ScVal{Type: xdr.ScValTypeScvU64, U64: xdr.Uint64Ptr(999)},
			},
		},
	}

	changes := xdr.LedgerEntryChanges{
		{
			Type:    xdr.LedgerEntryChangeTypeLedgerEntryCreated,
			Created: &accountEntry,
		},
		{
			Type:    xdr.LedgerEntryChangeTypeLedgerEntryUpdated,
			Updated: &contractEntry,
		},
	}

	entries := make(map[string]string)
	extractFromChanges(changes, entries)

	if len(entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(entries))
	}
}
