package verifreg

import (
	"github.com/post-quantumqoin/address"

	"github.com/post-quantumqoin/core-types/abi"
	"github.com/post-quantumqoin/core-types/builtin"
)

var Methods = map[abi.MethodNum]builtin.MethodMeta{
	1: {"Constructor", *new(func(*address.Address) *abi.EmptyValue)},                          // Constructor
	2: {"AddVerifier", *new(func(*AddVerifierParams) *abi.EmptyValue)},                        // AddVerifier
	3: {"RemoveVerifier", *new(func(*address.Address) *abi.EmptyValue)},                       // RemoveVerifier
	4: {"AddVerifiedClient", *new(func(*AddVerifiedClientParams) *abi.EmptyValue)},            // AddVerifiedClient
	5: {"UseBytes", *new(func(*UseBytesParams) *abi.EmptyValue)},                              // UseBytes
	6: {"RestoreBytes", *new(func(*RestoreBytesParams) *abi.EmptyValue)},                      // RestoreBytes
	7: {"RemoveVerifiedClientDataCap", *new(func(*RemoveDataCapParams) *RemoveDataCapReturn)}, // RemoveVerifiedClientDataCap
}
