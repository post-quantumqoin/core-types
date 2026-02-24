package evm

import (
	"github.com/ipfs/go-cid"
	xerrors "golang.org/x/xerrors"

	"github.com/post-quantumqoin/core-types/abi"
	"github.com/post-quantumqoin/core-types/builtin"
	"github.com/post-quantumqoin/core-types/builtin/v14/util/adt"
)

type Tombstone struct {
	Origin abi.ActorID
	Nonce  uint64
}

type State struct {
	Bytecode      cid.Cid
	BytecodeHash  [32]byte
	ContractState cid.Cid
	Nonce         uint64
	Tombstone     *Tombstone
}

func ConstructState(store adt.Store, bytecode cid.Cid) (*State, error) {
	emptyMapCid, err := adt.StoreEmptyMap(store, builtin.DefaultHamtBitwidth)
	if err != nil {
		return nil, xerrors.Errorf("failed to create empty map: %w", err)
	}

	return &State{
		Bytecode:      bytecode,
		ContractState: emptyMapCid,
		Nonce:         0,
	}, nil
}
