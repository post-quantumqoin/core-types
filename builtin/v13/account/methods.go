package account

import (
	typegen "github.com/whyrusleeping/cbor-gen"

	"github.com/post-quantumqoin/address"
	"github.com/post-quantumqoin/core-types/abi"
	"github.com/post-quantumqoin/core-types/builtin"
)

var Methods = map[abi.MethodNum]builtin.MethodMeta{
	1: {"Constructor", *new(func(*address.Address) *abi.EmptyValue)},   // Constructor
	2: {"PubkeyAddress", *new(func(*abi.EmptyValue) *address.Address)}, // PubkeyAddress
	builtin.MustGenerateFRCMethodNum("AuthenticateMessage"): {"AuthenticateMessage", *new(func(*AuthenticateMessageParams) *typegen.CborBool)}, // AuthenticateMessage
}
