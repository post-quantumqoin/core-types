package reward

import (
	"github.com/post-quantumqoin/address"
	"github.com/post-quantumqoin/core-types/abi"
	"github.com/post-quantumqoin/core-types/builtin/v12/util/smoothing"
)

type AwardBlockRewardParams struct {
	Miner     address.Address
	Penalty   abi.TokenAmount // penalty for including bad messages in a block, >= 0
	GasReward abi.TokenAmount // gas reward from all gas fees in a block, >= 0
	WinCount  int64           // number of reward units won, > 0
}

type ThisEpochRewardReturn struct {
	ThisEpochRewardSmoothed smoothing.FilterEstimate
	ThisEpochBaselinePower  abi.StoragePower
}
