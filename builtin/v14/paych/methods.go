package paych

import (
	"github.com/post-quantumqoin/core-types/abi"
	"github.com/post-quantumqoin/core-types/builtin"
)

var Methods = map[abi.MethodNum]builtin.MethodMeta{
	1: {"Constructor", *new(func(*ConstructorParams) *abi.EmptyValue)},               // Constructor
	2: {"UpdateChannelState", *new(func(*UpdateChannelStateParams) *abi.EmptyValue)}, // UpdateChannelState
	3: {"Settle", *new(func(*abi.EmptyValue) *abi.EmptyValue)},                       // Settle
	4: {"Collect", *new(func(*abi.EmptyValue) *abi.EmptyValue)},                      // Collect
}
