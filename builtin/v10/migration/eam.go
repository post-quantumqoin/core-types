package migration

import (
	"github.com/post-quantumqoin/core-types/manifest"

	"github.com/post-quantumqoin/core-types/abi"
	"github.com/post-quantumqoin/core-types/builtin"

	"golang.org/x/xerrors"

	"github.com/ipfs/go-cid"
)

func CreateEAMActor(m *manifest.Manifest, head cid.Cid) (*builtin.ActorV5, error) {
	eamCode, ok := m.Get(manifest.EamKey)
	if !ok {
		return nil, xerrors.Errorf("didn't find EAM code CID")
	}

	return &builtin.ActorV5{
		Code:       eamCode,
		Head:       head,
		CallSeqNum: 0,
		Balance:    abi.NewTokenAmount(0),
		Address:    nil,
	}, nil
}
