package market

import (
	addr "github.com/post-quantumqoin/address"
	"github.com/post-quantumqoin/bitset"
	"github.com/post-quantumqoin/core-types/abi"
	cbg "github.com/whyrusleeping/cbor-gen"
)

type WithdrawBalanceParams struct {
	ProviderOrClientAddress addr.Address
	Amount                  abi.TokenAmount
}

type PublishStorageDealsParams struct {
	Deals []ClientDealProposal
}

type PublishStorageDealsReturn struct {
	IDs        []abi.DealID
	ValidDeals bitfield.BitField
}

// - Array of sectors rather than just one
// - Removed SectorStart (which is unknown at call time)
type VerifyDealsForActivationParams struct {
	Sectors []SectorDeals
}

type SectorDeals struct {
	SectorExpiry abi.ChainEpoch
	DealIDs      []abi.DealID
}

// - Array of sectors weights
type VerifyDealsForActivationReturn struct {
	Sectors []SectorWeights
}

type SectorWeights struct {
	DealSpace          uint64         // Total space in bytes of submitted deals.
	DealWeight         abi.DealWeight // Total space*time of submitted deals.
	VerifiedDealWeight abi.DealWeight // Total space*time of submitted verified deals.
}

type ActivateDealsParams struct {
	DealIDs      []abi.DealID
	SectorExpiry abi.ChainEpoch
}

type SectorDataSpec struct {
	DealIDs    []abi.DealID
	SectorType abi.RegisteredSealProof
}

type ComputeDataCommitmentParams struct {
	Inputs []*SectorDataSpec
}

type ComputeDataCommitmentReturn struct {
	CommDs []cbg.CborCid
}

type OnMinerSectorsTerminateParams struct {
	Epoch   abi.ChainEpoch
	DealIDs []abi.DealID
}
