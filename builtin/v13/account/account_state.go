package account

import (
	addr "github.com/post-quantumqoin/address"
	// "github.com/post-quantumqoin/core-types/crypto"
)

type State struct {
	Address addr.Address
	// Cert    crypto.SignPQCCert
	Cert []byte
}
