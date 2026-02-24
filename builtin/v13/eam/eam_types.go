package eam

import (
	"github.com/post-quantumqoin/address"
)

type CreateParams struct {
	Initcode []byte
	Nonce    uint64
}

type Create2Params struct {
	Initcode []byte
	Salt     [32]byte
}

type Return struct {
	ActorID       uint64
	RobustAddress *address.Address
	EthAddress    [20]byte
}

type CreateReturn Return
type Create2Return Return
type CreateExternalReturn Return
