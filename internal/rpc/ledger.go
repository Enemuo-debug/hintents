// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"encoding/base64"

	"github.com/stellar/go/xdr"
)

// LedgerEntryPair represents a ledger key-entry pair for simulation
type LedgerEntryPair struct {
	KeyXDR   string
	EntryXDR string
}

// EncodeLedgerKey encodes a LedgerKey to base64 XDR
func EncodeLedgerKey(key xdr.LedgerKey) (string, error) {
	xdrBytes, err := key.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(xdrBytes), nil
}

// EncodeLedgerEntry encodes a LedgerEntry to base64 XDR
func EncodeLedgerEntry(entry xdr.LedgerEntry) (string, error) {
	xdrBytes, err := entry.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(xdrBytes), nil
}

// ExtractLedgerEntriesFromMeta extracts ledger entries from TransactionResultMeta
// This provides the state that was present when the transaction executed
func ExtractLedgerEntriesFromMeta(resultMetaXDR string) (map[string]string, error) {
	// Decode the result meta XDR
	metaBytes, err := base64.StdEncoding.DecodeString(resultMetaXDR)
	if err != nil {
		return nil, err
	}

	var resultMeta xdr.TransactionResultMeta
	if err := resultMeta.UnmarshalBinary(metaBytes); err != nil {
		return nil, err
	}

	entries := make(map[string]string)

	// Extract entries from TransactionMeta
	switch meta := resultMeta.TxApplyProcessing.(type) {
	case xdr.TransactionMeta:
		// V0 or V1
		extractFromLedgerEntryChanges(meta.Operations, entries)

	case *xdr.TransactionMetaV2:
		// V2
		extractFromLedgerEntryChanges(meta.Operations, entries)

	case *xdr.TransactionMetaV3:
		// V3 (Soroban)
		extractFromLedgerEntryChanges(meta.Operations, entries)
		
		// Also extract from TxChangesBefore and TxChangesAfter
		extractFromChanges(meta.TxChangesBefore, entries)
		extractFromChanges(meta.TxChangesAfter, entries)
	}

	return entries, nil
}

// extractFromLedgerEntryChanges processes operation-level changes
func extractFromLedgerEntryChanges(operations []xdr.OperationMeta, entries map[string]string) {
	for _, op := range operations {
		extractFromChanges(op.Changes, entries)
	}
}

// extractFromChanges processes individual ledger entry changes
func extractFromChanges(changes xdr.LedgerEntryChanges, entries map[string]string) {
	for _, change := range changes {
		switch change.Type {
		case xdr.LedgerEntryChangeTypeLedgerEntryCreated:
			if change.Created != nil {
				addEntry(*change.Created, entries)
			}
		case xdr.LedgerEntryChangeTypeLedgerEntryUpdated:
			if change.Updated != nil {
				addEntry(*change.Updated, entries)
			}
		case xdr.LedgerEntryChangeTypeLedgerEntryState:
			if change.State != nil {
				addEntry(*change.State, entries)
			}
		}
	}
}

// addEntry adds a ledger entry to the map
func addEntry(entry xdr.LedgerEntry, entries map[string]string) {
	// Generate the key from the entry
	key := ledgerKeyFromEntry(entry)
	if key == nil {
		return
	}

	keyXDR, err := EncodeLedgerKey(*key)
	if err != nil {
		return
	}

	entryXDR, err := EncodeLedgerEntry(entry)
	if err != nil {
		return
	}

	entries[keyXDR] = entryXDR
}

// ledgerKeyFromEntry generates a LedgerKey from a LedgerEntry
func ledgerKeyFromEntry(entry xdr.LedgerEntry) *xdr.LedgerKey {
	switch entry.Data.Type {
	case xdr.LedgerEntryTypeAccount:
		if entry.Data.Account != nil {
			return &xdr.LedgerKey{
				Type: xdr.LedgerEntryTypeAccount,
				Account: &xdr.LedgerKeyAccount{
					AccountId: entry.Data.Account.AccountId,
				},
			}
		}

	case xdr.LedgerEntryTypeTrustline:
		if entry.Data.TrustLine != nil {
			return &xdr.LedgerKey{
				Type: xdr.LedgerEntryTypeTrustline,
				TrustLine: &xdr.LedgerKeyTrustLine{
					AccountId: entry.Data.TrustLine.AccountId,
					Asset:     entry.Data.TrustLine.Asset,
				},
			}
		}

	case xdr.LedgerEntryTypeOffer:
		if entry.Data.Offer != nil {
			return &xdr.LedgerKey{
				Type: xdr.LedgerEntryTypeOffer,
				Offer: &xdr.LedgerKeyOffer{
					SellerId: entry.Data.Offer.SellerId,
					OfferId:  entry.Data.Offer.OfferId,
				},
			}
		}

	case xdr.LedgerEntryTypeData:
		if entry.Data.Data != nil {
			return &xdr.LedgerKey{
				Type: xdr.LedgerEntryTypeData,
				Data: &xdr.LedgerKeyData{
					AccountId: entry.Data.Data.AccountId,
					DataName:  entry.Data.Data.DataName,
				},
			}
		}

	case xdr.LedgerEntryTypeClaimableBalance:
		if entry.Data.ClaimableBalance != nil {
			return &xdr.LedgerKey{
				Type: xdr.LedgerEntryTypeClaimableBalance,
				ClaimableBalance: &xdr.LedgerKeyClaimableBalance{
					BalanceId: entry.Data.ClaimableBalance.BalanceId,
				},
			}
		}

	case xdr.LedgerEntryTypeLiquidityPool:
		if entry.Data.LiquidityPool != nil {
			return &xdr.LedgerKey{
				Type: xdr.LedgerEntryTypeLiquidityPool,
				LiquidityPool: &xdr.LedgerKeyLiquidityPool{
					LiquidityPoolId: entry.Data.LiquidityPool.LiquidityPoolId,
				},
			}
		}

	case xdr.LedgerEntryTypeContractData:
		if entry.Data.ContractData != nil {
			return &xdr.LedgerKey{
				Type: xdr.LedgerEntryTypeContractData,
				ContractData: &xdr.LedgerKeyContractData{
					Contract:   entry.Data.ContractData.Contract,
					Key:        entry.Data.ContractData.Key,
					Durability: entry.Data.ContractData.Durability,
				},
			}
		}

	case xdr.LedgerEntryTypeContractCode:
		if entry.Data.ContractCode != nil {
			return &xdr.LedgerKey{
				Type: xdr.LedgerEntryTypeContractCode,
				ContractCode: &xdr.LedgerKeyContractCode{
					Hash: entry.Data.ContractCode.Hash,
				},
			}
		}

	case xdr.LedgerEntryTypeConfigSetting:
		if entry.Data.ConfigSetting != nil {
			return &xdr.LedgerKey{
				Type: xdr.LedgerEntryTypeConfigSetting,
				ConfigSetting: &xdr.LedgerKeyConfigSetting{
					ConfigSettingId: entry.Data.ConfigSetting.ConfigSettingId,
				},
			}
		}

	case xdr.LedgerEntryTypeTtl:
		if entry.Data.Ttl != nil {
			return &xdr.LedgerKey{
				Type: xdr.LedgerEntryTypeTtl,
				Ttl: &xdr.LedgerKeyTtl{
					KeyHash: entry.Data.Ttl.KeyHash,
				},
			}
		}
	}

	return nil
}
