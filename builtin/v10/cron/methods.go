package cron

import (
	"github.com/post-quantumqoin/core-types/abi"
	"github.com/post-quantumqoin/core-types/builtin"
)

var Methods = map[abi.MethodNum]builtin.MethodMeta{
	1: {"Constructor", *new(func(*ConstructorParams) *abi.EmptyValue)}, // Constructor
	2: {"EpochTick", *new(func(*abi.EmptyValue) *abi.EmptyValue)},      // EpochTick
}
