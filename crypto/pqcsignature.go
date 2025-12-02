package crypto

import (
	"bytes"
	"fmt"
	"io"
	"math"

	cbg "github.com/whyrusleeping/cbor-gen"
	"golang.org/x/xerrors"
)

type SigType byte

// Falcon1024CryptoPkBytes + Falcon1024CryptoSignBytes + Dilithium5CryptoPkBytes + Dilithium5CryptoSignBytes+other
const MultiPqcSigLen = 897 + 692 + 1952 + 3293 + 20
const (
	SigTypeUnknown = SigType(math.MaxUint8)

	SigTypeSecp256k1 = SigType(iota)
	SigTypeBLS

	SigTypeDelegated
	SigTypeMultiPqc

	SigTypeFalcon512
	SigTypeFalcon1024
	SigTypeDilithium3
	SigTypeDilithium5
)

func (t SigType) Name() (string, error) {
	switch t {
	case SigTypeUnknown:
		return "unknown", nil
	case SigTypeFalcon512:
		return "falcon512", nil
	case SigTypeFalcon1024:
		return "falcon1024", nil
	case SigTypeDilithium3:
		return "dilithium3", nil
	case SigTypeDilithium5:
		return "dilithium5", nil
	case SigTypeSecp256k1:
		return "secp256k1", nil
	case SigTypeBLS:
		return "bls", nil
	case SigTypeDelegated:
		return "delegated", nil
	default:
		return "", fmt.Errorf("invalid signature type: %d", t)
	}
}

func GetTypeByName(name string) SigType {
	switch name {
	case "falcon512":
		return SigTypeFalcon512
	case "falcon1024":
		return SigTypeFalcon1024
	case "dilithium3":
		return SigTypeDilithium3
	case "dilithium5":
		return SigTypeDilithium5
	case "secp256k1":
		return SigTypeSecp256k1
	case "bls":
		return SigTypeBLS
	case "delegated":
		return SigTypeDelegated
	default:
		return SigTypeUnknown
	}
}

const SignatureMaxLength = 10000

type SignPqcCertPubkey struct {
	Typ    string
	Pubkey []byte
}

type SignPQCCert struct {
	Pubkeys []SignPqcCertPubkey
	Version uint8
	// Nonce   []byte
}

type PqcSignature struct {
	Type SigType
	Data []byte
}

type Signature struct {
	Type          SigType
	Data          []byte
	PqcSignatures []PqcSignature
	PqcCert       SignPQCCert
}

func (s *Signature) Set(tp SigType, data []byte) error {
	switch tp {
	case SigTypeFalcon512:
		s.PqcSignatures = append(s.PqcSignatures, PqcSignature{Type: tp, Data: data})
	case SigTypeFalcon1024:
		s.PqcSignatures = append(s.PqcSignatures, PqcSignature{Type: tp, Data: data})
	case SigTypeDilithium3:
		s.PqcSignatures = append(s.PqcSignatures, PqcSignature{Type: tp, Data: data})
	case SigTypeDilithium5:
		s.PqcSignatures = append(s.PqcSignatures, PqcSignature{Type: tp, Data: data})
	default:
		return fmt.Errorf("invalid signature SigType")
	}
	return nil
}

func (s *Signature) Get(tp SigType) ([]byte, error) {
	for _, sgin := range s.PqcSignatures {
		if sgin.Type == tp {
			return sgin.Data, nil
		}
	}
	return nil, fmt.Errorf("find signature with type %d not found", tp)
}

func (s *Signature) Equals(o *Signature) bool {
	if s == nil || o == nil {
		return s == o
	}
	return s.Type == o.Type && bytes.Equal(s.Data, o.Data)
}
func (m *Signature) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := m.MarshalCBOR(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m *Signature) ChainLength() int {
	ser, err := m.Serialize()
	if err != nil {
		panic(err)
	}
	return len(ser)
}

var lengthBufSignPqcCertPubkey = []byte{130}

func (t *SignPqcCertPubkey) MarshalCBOR(w io.Writer) error {
	if t == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}

	cw := cbg.NewCborWriter(w)

	if _, err := cw.Write(lengthBufSignPqcCertPubkey); err != nil {
		return err
	}

	// t.Typ (string) (string)
	if len(t.Typ) > 8192 {
		return xerrors.Errorf("Value in field t.Typ was too long")
	}

	if err := cw.WriteMajorTypeHeader(cbg.MajTextString, uint64(len(t.Typ))); err != nil {
		return err
	}
	if _, err := cw.WriteString(string(t.Typ)); err != nil {
		return err
	}

	// t.Pubkey ([]uint8) (slice)
	if len(t.Pubkey) > 2097152 {
		return xerrors.Errorf("Byte array in field t.Falcon512PublicKey was too long")
	}

	if err := cw.WriteMajorTypeHeader(cbg.MajByteString, uint64(len(t.Pubkey))); err != nil {
		return err
	}

	if _, err := cw.Write(t.Pubkey); err != nil {
		return err
	}

	return nil
}

func (t *SignPqcCertPubkey) UnmarshalCBOR(r io.Reader) (err error) {
	*t = SignPqcCertPubkey{}

	cr := cbg.NewCborReader(r)

	maj, extra, err := cr.ReadHeader()
	if err != nil {
		return err
	}
	defer func() {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	if maj != cbg.MajArray {
		return fmt.Errorf("cbor input should be of type array")
	}

	if extra != 2 {
		return fmt.Errorf("cbor input had wrong number of fields")
	}

	// t.Typ (string) (string)
	{
		sval, err := cbg.ReadStringWithMax(cr, 8192)
		if err != nil {
			return err
		}

		t.Typ = string(sval)
	}

	// t.Pubkey ([]uint8) (slice)
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}

	if extra > 2097152 {
		return fmt.Errorf("t.Falcon512PublicKey: byte array too large (%d)", extra)
	}
	if maj != cbg.MajByteString {
		return fmt.Errorf("expected byte array")
	}

	if extra > 0 {
		t.Pubkey = make([]uint8, extra)
	}

	if _, err := io.ReadFull(cr, t.Pubkey); err != nil {
		return err
	}

	return nil
}

var lengthBufSignPQCCert = []byte{130}

func (t *SignPQCCert) MarshalCBOR(w io.Writer) error {
	if t == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}

	cw := cbg.NewCborWriter(w)

	if _, err := cw.Write(lengthBufSignPQCCert); err != nil {
		return err
	}

	// t.Pubkeys ([]SignPqcCertPubkey) (slice)
	if len(t.Pubkeys) > 8192 {
		return xerrors.Errorf("Slice value in field t.BeaconEntries was too long")
	}

	if err := cw.WriteMajorTypeHeader(cbg.MajArray, uint64(len(t.Pubkeys))); err != nil {
		return err
	}
	for _, v := range t.Pubkeys {
		if err := v.MarshalCBOR(cw); err != nil {
			return err
		}

	}
	// t.Version (uint8) (uint8)
	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(t.Version)); err != nil {
		return err
	}

	// t.Nonce ([]uint8) (slice)
	// if len(t.Nonce) > 2097152 {
	// 	return xerrors.Errorf("Byte array in field t.Nonce was too long")
	// }

	// if err := cw.WriteMajorTypeHeader(cbg.MajByteString, uint64(len(t.Nonce))); err != nil {
	// 	return err
	// }

	// if _, err := cw.Write(t.Nonce); err != nil {
	// 	return err
	// }

	return nil
}

func (t *SignPQCCert) UnmarshalCBOR(r io.Reader) (err error) {
	*t = SignPQCCert{}

	cr := cbg.NewCborReader(r)

	maj, extra, err := cr.ReadHeader()
	if err != nil {
		return err
	}
	defer func() {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	if maj != cbg.MajArray {
		return fmt.Errorf("cbor input should be of type array")
	}

	if extra != 2 {
		return fmt.Errorf("cbor input had wrong number of fields")
	}

	// t.Pubkeys ([]PqcCertPubkey) (slice)

	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}

	if extra > 8192 {
		return fmt.Errorf("t.PqcCertPubkey: array too large (%d)", extra)
	}

	if maj != cbg.MajArray {
		return fmt.Errorf("expected cbor array")
	}

	if extra > 0 {
		t.Pubkeys = make([]SignPqcCertPubkey, extra)
	}

	for i := 0; i < int(extra); i++ {
		{
			var maj byte
			var extra uint64
			var err error
			_ = maj
			_ = extra
			_ = err

			{

				if err := t.Pubkeys[i].UnmarshalCBOR(cr); err != nil {
					return xerrors.Errorf("unmarshaling t.Pubkeys[i]: %w", err)
				}

			}

		}
	}

	// t.Version (uint8) (uint8)
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	if maj != cbg.MajUnsignedInt {
		return fmt.Errorf("wrong type for uint8 field")
	}
	if extra > math.MaxUint8 {
		return fmt.Errorf("integer in input was too large for uint8 field")
	}
	t.Version = uint8(extra)

	// t.Nonce ([]uint8) (slice)
	// maj, extra, err = cr.ReadHeader()
	// if err != nil {
	// 	return err
	// }

	// if extra > 2097152 {
	// 	return fmt.Errorf("t.Nonce: byte array too large (%d)", extra)
	// }
	// if maj != cbg.MajByteString {
	// 	return fmt.Errorf("expected byte array")
	// }

	// if extra > 0 {
	// 	t.Nonce = make([]uint8, extra)
	// }

	// if _, err := io.ReadFull(cr, t.Nonce); err != nil {
	// 	return err
	// }

	return nil
}

var lengthBufPqcSignature = []byte{130}

func (t *PqcSignature) MarshalCBOR(w io.Writer) error {
	if t == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}

	cw := cbg.NewCborWriter(w)

	if _, err := cw.Write(lengthBufPqcSignature); err != nil {
		return err
	}

	// t.Type (uint8)
	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(t.Type)); err != nil {
		return err
	}

	// t.Data ([]uint8) (slice)
	if len(t.Data) > 2097152 {
		return xerrors.Errorf("Byte array in field t.Falcon512PublicKey was too long")
	}

	if err := cw.WriteMajorTypeHeader(cbg.MajByteString, uint64(len(t.Data))); err != nil {
		return err
	}

	if _, err := cw.Write(t.Data); err != nil {
		return err
	}

	return nil
}

func (t *PqcSignature) UnmarshalCBOR(r io.Reader) (err error) {
	*t = PqcSignature{}

	cr := cbg.NewCborReader(r)

	maj, extra, err := cr.ReadHeader()
	if err != nil {
		return err
	}
	defer func() {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	if maj != cbg.MajArray {
		return fmt.Errorf("cbor input should be of type array")
	}

	if extra != 2 {
		return fmt.Errorf("cbor input had wrong number of fields")
	}

	// t.Type (uint8)
	{

		maj, extra, err = cr.ReadHeader()
		if err != nil {
			return err
		}
		if maj != cbg.MajUnsignedInt {
			return fmt.Errorf("wrong type for uint64 field")
		}
		t.Type = SigType(extra)

	}
	// t.Data ([]uint8) (slice)
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}

	if extra > 2097152 {
		return fmt.Errorf("t.Data: byte array too large (%d)", extra)
	}
	if maj != cbg.MajByteString {
		return fmt.Errorf("expected byte array")
	}

	if extra > 0 {
		t.Data = make([]uint8, extra)
	}

	if _, err := io.ReadFull(cr, t.Data); err != nil {
		return err
	}

	return nil
}

var lengthBufSignature = []byte{132}

func (t *Signature) MarshalCBOR(w io.Writer) error {
	if t == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}

	cw := cbg.NewCborWriter(w)

	if _, err := cw.Write(lengthBufSignature); err != nil {
		return err
	}

	// t.Type (uint8)

	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(t.Type)); err != nil {
		return err
	}

	// t.Data ([]uint8) (slice)
	if len(t.Data) > 2097152 {
		return xerrors.Errorf("Byte array in field t.Falcon512PublicKey was too long")
	}

	if err := cw.WriteMajorTypeHeader(cbg.MajByteString, uint64(len(t.Data))); err != nil {
		return err
	}

	if _, err := cw.Write(t.Data); err != nil {
		return err
	}

	// t.PqcSignatures ([]types.PqcSignature) (slice)
	if len(t.PqcSignatures) > 8192 {
		return xerrors.Errorf("Slice value in field t.PqcSignatures was too long")
	}

	if err := cw.WriteMajorTypeHeader(cbg.MajArray, uint64(len(t.PqcSignatures))); err != nil {
		return err
	}
	for _, v := range t.PqcSignatures {
		if err := v.MarshalCBOR(cw); err != nil {
			return err
		}

	}

	// t.SignPQCCert (SignPQCCert) (struct)
	if err := t.PqcCert.MarshalCBOR(cw); err != nil {
		return err
	}

	return nil
}

func (t *Signature) UnmarshalCBOR(r io.Reader) (err error) {
	*t = Signature{}

	cr := cbg.NewCborReader(r)

	maj, extra, err := cr.ReadHeader()
	if err != nil {
		return err
	}
	defer func() {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	if maj != cbg.MajArray {
		return fmt.Errorf("cbor input should be of type array")
	}

	if extra != 4 {
		return fmt.Errorf("cbor input had wrong number of fields")
	}
	// fmt.Println("Signature t.Type ")
	// t.Type (uint8)
	{
		maj, extra, err = cr.ReadHeader()
		if err != nil {
			return err
		}
		if maj != cbg.MajUnsignedInt {
			return fmt.Errorf("wrong type for uint64 field")
		}
		t.Type = SigType(extra)
	}
	// fmt.Println("Signature t.Data ")
	// t.Data ([]uint8) (slice)
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}

	if extra > 2097152 {
		return fmt.Errorf("t.Data: byte array too large (%d)", extra)
	}
	if maj != cbg.MajByteString {
		return fmt.Errorf("expected byte array")
	}

	if extra > 0 {
		t.Data = make([]uint8, extra)
	}

	if _, err := io.ReadFull(cr, t.Data); err != nil {
		return err
	}
	// fmt.Println("Signature t.PqcSignatures ")
	// t.PqcSignatures (PqcSignature) (slice)
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}

	if extra > 8192 {
		return fmt.Errorf("t.BeaconEntries: array too large (%d)", extra)
	}

	if maj != cbg.MajArray {
		return fmt.Errorf("expected cbor array")
	}

	if extra > 0 {
		t.PqcSignatures = make([]PqcSignature, extra)
	}

	for i := 0; i < int(extra); i++ {
		{
			var maj byte
			var extra uint64
			var err error
			_ = maj
			_ = extra
			_ = err

			{

				if err := t.PqcSignatures[i].UnmarshalCBOR(cr); err != nil {
					return xerrors.Errorf("unmarshaling t.PqcSignatures[i]: %w", err)
				}

			}

		}
	}
	// t.PqcCert (crypto.PqcCert) (struct)
	{

		b, err := cr.ReadByte()
		if err != nil {
			return err
		}
		if b != cbg.CborNull[0] {
			if err := cr.UnreadByte(); err != nil {
				return err
			}
			t.PqcCert = SignPQCCert{}
			if err := t.PqcCert.UnmarshalCBOR(cr); err != nil {
				return xerrors.Errorf("unmarshaling t.SignPQCCert pointer: %w", err)
			}
		}

	}
	return nil
}

// func (s *Signature) MarshalCBOR(w io.Writer) error {
// 	if s == nil {
// 		_, err := w.Write(cbg.CborNull)
// 		return err
// 	}
// 	var pqcsgl int
// 	for _, sgin := range s.PqcSignatures {
// 		pqcsgl += len(sgin.Data) + 1
// 	}

// 	header := cbg.CborEncodeMajorType(cbg.MajByteString, uint64(len(s.Data)+1+pqcsgl))
// 	if _, err := w.Write(header); err != nil {
// 		return err
// 	}
// 	if _, err := w.Write([]byte{byte(s.Type)}); err != nil {
// 		return err
// 	}
// 	if _, err := w.Write(s.Data); err != nil {
// 		return err
// 	}
// 	for _, sgin := range s.PqcSignatures {
// 		if _, err := w.Write([]byte{byte(sgin.Type)}); err != nil {
// 			return err
// 		}
// 		if _, err := w.Write(sgin.Data); err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

// func (s *Signature) UnmarshalCBOR(br io.Reader) error {
// 	maj, l, err := cbg.CborReadHeader(br)
// 	if err != nil {
// 		return err
// 	}

// 	if maj != cbg.MajByteString {
// 		return fmt.Errorf("not a byte string")
// 	}
// 	// if l > SignatureMaxLength {
// 	// 	return fmt.Errorf("string too long")
// 	// }
// 	if l == 0 {
// 		return fmt.Errorf("string empty")
// 	}
// 	buf := make([]byte, l)
// 	if _, err = io.ReadFull(br, buf); err != nil {
// 		return err
// 	}
// 	switch SigType(buf[0]) {
// 	default:
// 		return fmt.Errorf("invalid signature type in cbor input: %d", buf[0])
// 	case SigTypeFalcon512:
// 		s.Type = SigTypeFalcon512
// 	case SigTypeFalcon1024:
// 		s.Type = SigTypeFalcon1024
// 	case SigTypeDilithium3:
// 		s.Type = SigTypeDilithium3
// 	case SigTypeDilithium5:
// 		s.Type = SigTypeDilithium5
// 	}
// 	s.Data = buf[1:]

// 	return nil
// }

// func (s *Signature) MarshalBinary() ([]byte, error) {
// 	bs := make([]byte, len(s.Data)+1)
// 	bs[0] = byte(s.Type)
// 	copy(bs[1:], s.Data)
// 	return bs, nil
// }

// func (s *Signature) UnmarshalBinary(bs []byte) error {
// 	if len(bs) > SignatureMaxLength {
// 		return fmt.Errorf("invalid signature bytes, too long (%d)", len(bs))
// 	}
// 	if len(bs) == 0 {
// 		return fmt.Errorf("invalid signature bytes of length 0")
// 	}
// 	switch SigType(bs[0]) {
// 	default:
// 		// Do not error during unmarshal but leave a standard value.
// 		// unmarshal(marshal(zero valued sig)) is valuable for test
// 		// and type needs to be checked by caller anyway.
// 		s.Type = SigTypeUnknown
// 	case SigTypeFalcon512:
// 		s.Type = SigTypeFalcon512
// 	case SigTypeFalcon1024:
// 		s.Type = SigTypeFalcon1024
// 	case SigTypeDilithium3:
// 		s.Type = SigTypeDilithium3
// 	case SigTypeDilithium5:
// 		s.Type = SigTypeDilithium5
// 	}
// 	s.Data = bs[1:]

// 	return nil
// }
