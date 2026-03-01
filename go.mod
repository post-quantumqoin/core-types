module github.com/post-quantumqoin/core-types

go 1.22.2

require (
	github.com/filecoin-project/go-amt-ipld/v4 v4.2.0
	github.com/filecoin-project/go-hamt-ipld/v3 v3.1.0
	github.com/ipfs/go-block-format v0.0.3
	github.com/ipfs/go-cid v0.3.2
	github.com/ipfs/go-ipld-cbor v0.0.6
	github.com/ipld/go-ipld-prime v0.19.0
	github.com/minio/blake2b-simd v0.0.0-20160723061019-3f5f724cb5b1
	github.com/minio/sha256-simd v1.0.1
	github.com/multiformats/go-multibase v0.0.3
	github.com/multiformats/go-multihash v0.2.1
	github.com/multiformats/go-varint v0.0.6
	github.com/post-quantumqoin/address v0.1.0
	github.com/post-quantumqoin/bitset v0.1.1
	github.com/post-quantumqoin/go-commp-tools/nonffi v0.0.0-20260301130547-d3e4242693b1
	github.com/stretchr/testify v1.7.0
	github.com/whyrusleeping/cbor-gen v0.1.0
	golang.org/x/crypto v0.1.0
	golang.org/x/sync v0.0.0-20220722155255-886fb9371eb4
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/filecoin-project/go-fil-commcid v0.1.0 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20190812055157-5d271430af9f // indirect
	github.com/ipfs/go-ipfs-util v0.0.2 // indirect
	github.com/ipfs/go-ipld-format v0.3.0 // indirect
	github.com/ipfs/go-log v1.0.4 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/klauspost/cpuid/v2 v2.2.3 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.0.3 // indirect
	github.com/multiformats/go-base36 v0.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/polydawn/refmt v0.0.0-20201211092308-30ac6d18308e // indirect
	github.com/post-quantumqoin/go-commp-tools v0.1.0 // indirect
	github.com/post-quantumqoin/go-qoin-commcid v0.0.0-20260301120253-efbe8a9fa094 // indirect
	github.com/post-quantumqoin/qvm v0.0.0-20260228084346-a0b85c0b3ce2 // indirect
	github.com/smartystreets/assertions v1.0.1 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	golang.org/x/sys v0.1.0 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	lukechampine.com/blake3 v1.1.6 // indirect
)

replace github.com/filecoin-project/go-state-types => github.com/post-quantumqoin/core-types v0.4.2
