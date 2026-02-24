package ethaccount

import (
	"github.com/post-quantumqoin/core-types/abi"
	"github.com/post-quantumqoin/core-types/builtin"
)

var Methods = map[abi.MethodNum]builtin.MethodMeta{
	1: {"Constructor", *new(func(value *abi.EmptyValue) *abi.EmptyValue)},
}
