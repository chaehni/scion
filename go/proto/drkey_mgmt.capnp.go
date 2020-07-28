// Code generated by capnpc-go. DO NOT EDIT.

package proto

import (
	strconv "strconv"

	capnp "zombiezen.com/go/capnproto2"
	text "zombiezen.com/go/capnproto2/encoding/text"
	schemas "zombiezen.com/go/capnproto2/schemas"
)

type DRKeyReq struct{ capnp.Struct }
type DRKeyReq_flags DRKeyReq

// DRKeyReq_TypeID is the unique identifier for the type DRKeyReq.
const DRKeyReq_TypeID = 0x9f50d21c9d4ce7ef

func NewDRKeyReq(s *capnp.Segment) (DRKeyReq, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 24, PointerCount: 1})
	return DRKeyReq{st}, err
}

func NewRootDRKeyReq(s *capnp.Segment) (DRKeyReq, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 24, PointerCount: 1})
	return DRKeyReq{st}, err
}

func ReadRootDRKeyReq(msg *capnp.Message) (DRKeyReq, error) {
	root, err := msg.RootPtr()
	return DRKeyReq{root.Struct()}, err
}

func (s DRKeyReq) String() string {
	str, _ := text.Marshal(0x9f50d21c9d4ce7ef, s.Struct)
	return str
}

func (s DRKeyReq) Isdas() uint64 {
	return s.Struct.Uint64(0)
}

func (s DRKeyReq) SetIsdas(v uint64) {
	s.Struct.SetUint64(0, v)
}

func (s DRKeyReq) Timestamp() uint32 {
	return s.Struct.Uint32(8)
}

func (s DRKeyReq) SetTimestamp(v uint32) {
	s.Struct.SetUint32(8, v)
}

func (s DRKeyReq) Signature() ([]byte, error) {
	p, err := s.Struct.Ptr(0)
	return []byte(p.Data()), err
}

func (s DRKeyReq) HasSignature() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s DRKeyReq) SetSignature(v []byte) error {
	return s.Struct.SetData(0, v)
}

func (s DRKeyReq) CertVer() uint32 {
	return s.Struct.Uint32(12)
}

func (s DRKeyReq) SetCertVer(v uint32) {
	s.Struct.SetUint32(12, v)
}

func (s DRKeyReq) TrcVer() uint32 {
	return s.Struct.Uint32(16)
}

func (s DRKeyReq) SetTrcVer(v uint32) {
	s.Struct.SetUint32(16, v)
}

func (s DRKeyReq) Flags() DRKeyReq_flags { return DRKeyReq_flags(s) }

func (s DRKeyReq_flags) Prefetch() bool {
	return s.Struct.Bit(160)
}

func (s DRKeyReq_flags) SetPrefetch(v bool) {
	s.Struct.SetBit(160, v)
}

// DRKeyReq_List is a list of DRKeyReq.
type DRKeyReq_List struct{ capnp.List }

// NewDRKeyReq creates a new list of DRKeyReq.
func NewDRKeyReq_List(s *capnp.Segment, sz int32) (DRKeyReq_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 24, PointerCount: 1}, sz)
	return DRKeyReq_List{l}, err
}

func (s DRKeyReq_List) At(i int) DRKeyReq { return DRKeyReq{s.List.Struct(i)} }

func (s DRKeyReq_List) Set(i int, v DRKeyReq) error { return s.List.SetStruct(i, v.Struct) }

func (s DRKeyReq_List) String() string {
	str, _ := text.MarshalList(0x9f50d21c9d4ce7ef, s.List)
	return str
}

// DRKeyReq_Promise is a wrapper for a DRKeyReq promised by a client call.
type DRKeyReq_Promise struct{ *capnp.Pipeline }

func (p DRKeyReq_Promise) Struct() (DRKeyReq, error) {
	s, err := p.Pipeline.Struct()
	return DRKeyReq{s}, err
}

func (p DRKeyReq_Promise) Flags() DRKeyReq_flags_Promise { return DRKeyReq_flags_Promise{p.Pipeline} }

// DRKeyReq_flags_Promise is a wrapper for a DRKeyReq_flags promised by a client call.
type DRKeyReq_flags_Promise struct{ *capnp.Pipeline }

func (p DRKeyReq_flags_Promise) Struct() (DRKeyReq_flags, error) {
	s, err := p.Pipeline.Struct()
	return DRKeyReq_flags{s}, err
}

type DRKeyRep struct{ capnp.Struct }

// DRKeyRep_TypeID is the unique identifier for the type DRKeyRep.
const DRKeyRep_TypeID = 0xc3fe25dd82681d64

func NewDRKeyRep(s *capnp.Segment) (DRKeyRep, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 32, PointerCount: 2})
	return DRKeyRep{st}, err
}

func NewRootDRKeyRep(s *capnp.Segment) (DRKeyRep, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 32, PointerCount: 2})
	return DRKeyRep{st}, err
}

func ReadRootDRKeyRep(msg *capnp.Message) (DRKeyRep, error) {
	root, err := msg.RootPtr()
	return DRKeyRep{root.Struct()}, err
}

func (s DRKeyRep) String() string {
	str, _ := text.Marshal(0xc3fe25dd82681d64, s.Struct)
	return str
}

func (s DRKeyRep) Isdas() uint64 {
	return s.Struct.Uint64(0)
}

func (s DRKeyRep) SetIsdas(v uint64) {
	s.Struct.SetUint64(0, v)
}

func (s DRKeyRep) Timestamp() uint32 {
	return s.Struct.Uint32(8)
}

func (s DRKeyRep) SetTimestamp(v uint32) {
	s.Struct.SetUint32(8, v)
}

func (s DRKeyRep) ExpTime() uint32 {
	return s.Struct.Uint32(12)
}

func (s DRKeyRep) SetExpTime(v uint32) {
	s.Struct.SetUint32(12, v)
}

func (s DRKeyRep) Cipher() ([]byte, error) {
	p, err := s.Struct.Ptr(0)
	return []byte(p.Data()), err
}

func (s DRKeyRep) HasCipher() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s DRKeyRep) SetCipher(v []byte) error {
	return s.Struct.SetData(0, v)
}

func (s DRKeyRep) Signature() ([]byte, error) {
	p, err := s.Struct.Ptr(1)
	return []byte(p.Data()), err
}

func (s DRKeyRep) HasSignature() bool {
	p, err := s.Struct.Ptr(1)
	return p.IsValid() || err != nil
}

func (s DRKeyRep) SetSignature(v []byte) error {
	return s.Struct.SetData(1, v)
}

func (s DRKeyRep) CertVerSrc() uint32 {
	return s.Struct.Uint32(16)
}

func (s DRKeyRep) SetCertVerSrc(v uint32) {
	s.Struct.SetUint32(16, v)
}

func (s DRKeyRep) CertVerDst() uint32 {
	return s.Struct.Uint32(20)
}

func (s DRKeyRep) SetCertVerDst(v uint32) {
	s.Struct.SetUint32(20, v)
}

func (s DRKeyRep) TrcVer() uint32 {
	return s.Struct.Uint32(24)
}

func (s DRKeyRep) SetTrcVer(v uint32) {
	s.Struct.SetUint32(24, v)
}

// DRKeyRep_List is a list of DRKeyRep.
type DRKeyRep_List struct{ capnp.List }

// NewDRKeyRep creates a new list of DRKeyRep.
func NewDRKeyRep_List(s *capnp.Segment, sz int32) (DRKeyRep_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 32, PointerCount: 2}, sz)
	return DRKeyRep_List{l}, err
}

func (s DRKeyRep_List) At(i int) DRKeyRep { return DRKeyRep{s.List.Struct(i)} }

func (s DRKeyRep_List) Set(i int, v DRKeyRep) error { return s.List.SetStruct(i, v.Struct) }

func (s DRKeyRep_List) String() string {
	str, _ := text.MarshalList(0xc3fe25dd82681d64, s.List)
	return str
}

// DRKeyRep_Promise is a wrapper for a DRKeyRep promised by a client call.
type DRKeyRep_Promise struct{ *capnp.Pipeline }

func (p DRKeyRep_Promise) Struct() (DRKeyRep, error) {
	s, err := p.Pipeline.Struct()
	return DRKeyRep{s}, err
}

type DRKeyMgmt struct{ capnp.Struct }
type DRKeyMgmt_Which uint16

const (
	DRKeyMgmt_Which_unset    DRKeyMgmt_Which = 0
	DRKeyMgmt_Which_drkeyReq DRKeyMgmt_Which = 1
	DRKeyMgmt_Which_drkeyRep DRKeyMgmt_Which = 2
)

func (w DRKeyMgmt_Which) String() string {
	const s = "unsetdrkeyReqdrkeyRep"
	switch w {
	case DRKeyMgmt_Which_unset:
		return s[0:5]
	case DRKeyMgmt_Which_drkeyReq:
		return s[5:13]
	case DRKeyMgmt_Which_drkeyRep:
		return s[13:21]

	}
	return "DRKeyMgmt_Which(" + strconv.FormatUint(uint64(w), 10) + ")"
}

// DRKeyMgmt_TypeID is the unique identifier for the type DRKeyMgmt.
const DRKeyMgmt_TypeID = 0xb1bdb7d6fb13f1ca

func NewDRKeyMgmt(s *capnp.Segment) (DRKeyMgmt, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1})
	return DRKeyMgmt{st}, err
}

func NewRootDRKeyMgmt(s *capnp.Segment) (DRKeyMgmt, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1})
	return DRKeyMgmt{st}, err
}

func ReadRootDRKeyMgmt(msg *capnp.Message) (DRKeyMgmt, error) {
	root, err := msg.RootPtr()
	return DRKeyMgmt{root.Struct()}, err
}

func (s DRKeyMgmt) String() string {
	str, _ := text.Marshal(0xb1bdb7d6fb13f1ca, s.Struct)
	return str
}

func (s DRKeyMgmt) Which() DRKeyMgmt_Which {
	return DRKeyMgmt_Which(s.Struct.Uint16(0))
}
func (s DRKeyMgmt) SetUnset() {
	s.Struct.SetUint16(0, 0)

}

func (s DRKeyMgmt) DrkeyReq() (DRKeyReq, error) {
	if s.Struct.Uint16(0) != 1 {
		panic("Which() != drkeyReq")
	}
	p, err := s.Struct.Ptr(0)
	return DRKeyReq{Struct: p.Struct()}, err
}

func (s DRKeyMgmt) HasDrkeyReq() bool {
	if s.Struct.Uint16(0) != 1 {
		return false
	}
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s DRKeyMgmt) SetDrkeyReq(v DRKeyReq) error {
	s.Struct.SetUint16(0, 1)
	return s.Struct.SetPtr(0, v.Struct.ToPtr())
}

// NewDrkeyReq sets the drkeyReq field to a newly
// allocated DRKeyReq struct, preferring placement in s's segment.
func (s DRKeyMgmt) NewDrkeyReq() (DRKeyReq, error) {
	s.Struct.SetUint16(0, 1)
	ss, err := NewDRKeyReq(s.Struct.Segment())
	if err != nil {
		return DRKeyReq{}, err
	}
	err = s.Struct.SetPtr(0, ss.Struct.ToPtr())
	return ss, err
}

func (s DRKeyMgmt) DrkeyRep() (DRKeyRep, error) {
	if s.Struct.Uint16(0) != 2 {
		panic("Which() != drkeyRep")
	}
	p, err := s.Struct.Ptr(0)
	return DRKeyRep{Struct: p.Struct()}, err
}

func (s DRKeyMgmt) HasDrkeyRep() bool {
	if s.Struct.Uint16(0) != 2 {
		return false
	}
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s DRKeyMgmt) SetDrkeyRep(v DRKeyRep) error {
	s.Struct.SetUint16(0, 2)
	return s.Struct.SetPtr(0, v.Struct.ToPtr())
}

// NewDrkeyRep sets the drkeyRep field to a newly
// allocated DRKeyRep struct, preferring placement in s's segment.
func (s DRKeyMgmt) NewDrkeyRep() (DRKeyRep, error) {
	s.Struct.SetUint16(0, 2)
	ss, err := NewDRKeyRep(s.Struct.Segment())
	if err != nil {
		return DRKeyRep{}, err
	}
	err = s.Struct.SetPtr(0, ss.Struct.ToPtr())
	return ss, err
}

// DRKeyMgmt_List is a list of DRKeyMgmt.
type DRKeyMgmt_List struct{ capnp.List }

// NewDRKeyMgmt creates a new list of DRKeyMgmt.
func NewDRKeyMgmt_List(s *capnp.Segment, sz int32) (DRKeyMgmt_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1}, sz)
	return DRKeyMgmt_List{l}, err
}

func (s DRKeyMgmt_List) At(i int) DRKeyMgmt { return DRKeyMgmt{s.List.Struct(i)} }

func (s DRKeyMgmt_List) Set(i int, v DRKeyMgmt) error { return s.List.SetStruct(i, v.Struct) }

func (s DRKeyMgmt_List) String() string {
	str, _ := text.MarshalList(0xb1bdb7d6fb13f1ca, s.List)
	return str
}

// DRKeyMgmt_Promise is a wrapper for a DRKeyMgmt promised by a client call.
type DRKeyMgmt_Promise struct{ *capnp.Pipeline }

func (p DRKeyMgmt_Promise) Struct() (DRKeyMgmt, error) {
	s, err := p.Pipeline.Struct()
	return DRKeyMgmt{s}, err
}

func (p DRKeyMgmt_Promise) DrkeyReq() DRKeyReq_Promise {
	return DRKeyReq_Promise{Pipeline: p.Pipeline.GetPipeline(0)}
}

func (p DRKeyMgmt_Promise) DrkeyRep() DRKeyRep_Promise {
	return DRKeyRep_Promise{Pipeline: p.Pipeline.GetPipeline(0)}
}

const schema_f85d2602085656c1 = "x\xda\x84\x92OHT]\x18\xc6\xdf\xe7}\xef\x9dQ" +
	"p`\x0e3\x1f\xc8\xc7\xf7a\x9b\x846\x92\xbas\xa3" +
	"\x84B\x7f\x0c<\xa3(D\x12\xc3x\x1c\x87\x1a\xb9\xde" +
	"{\x85\xdc$\xb5k\xd1\xaeM\x90d\x90\xe0\xa2(\xa1" +
	"\xa8E-\xa2E\x10m\x1a*,\x12\x12\x94Z$\x15" +
	"\x14\x08\xa17\x8eW\xc7!\x94v3\xcfy\xce{\x9f" +
	"\xe7\xfc\xde\xc3C\xe8\xe2V\xb7\x08\"\x9dv\x13\xd1\xd7" +
	"O\xbd3\xffU\xfan\x90V\x90\xe8\xe9\xe0`\x1d7" +
	"\x0f\xaf\x93\x8b$\x91\xbaVQsI\xa2\xd6\x9bC " +
	"D/\xbeg~\xbd}\xf8d\xc1Z\xb1k\xedAR" +
	"\x882\xef\xf0>\xb3joe\x96q\x97\x10\x8d\xfc?" +
	"vi\xe9\xe0\xe63\xebvj\x06\xb3\xb5\\\xe4J\xe6" +
	"\x8a\xfd\xd5~\x99\x9f\xdb\xd9\x8f\x9b\x0f\x05\x17\xd6\xe6+" +
	"\xa4\xff\x85\xec\x86\xfa\x07I\x10\xb5\x0f;\x0cB&\xef" +
	"t\xda\xc1\xfeY3u\xa6\\\xe4r\xd8R\xc8{\xe3" +
	"^Gw\xee\x84\x99\xca\x19L\xf4\x01\xbaQ\x1c\"\x07" +
	"6}\x1b\x91\xbe*\xd0\xb3\x0c\x05\xce\xc2\x8a39\"" +
	"}]\xa0\xe7\x19Vc\"5g\xb5[\x02}\x8f\xa1" +
	"D\xb2\x10\"u\xe7\x08\x91\x9e\x17\xe8\xfb\x0c\xe58Y" +
	"8Dj\xa1\x83H\xdf\x16\xe8G\x0c\xb8\xa8\xc9\xad\x1e" +
	"\xb4\x117\x95\x82\x91|\x80zb\xd4\x13\xa2\xb0T6" +
	"A\x98/\x13<\xd4\x11\xa3\x8e\x10\x05\xa5\xe2x>\x9c" +
	"\xf4\x09\x06)b\xa4\x08\xd3\x05\xe3\x87\x83\xc6\xdf\xf1t" +
	"\x86~\xa1\xe6o\xd3\xe8\xb9|1\xd8\xaf\xf6\xc9\xa2\x94" +
	"C\xdb\xbbA\x9c\x86(\xda*\xdec\x8bw\x09t/" +
	"#\x85\xcd(n~\xec8\x91>*\xd0\x03\x8c\x14o" +
	"Dqwm\xd5>\x81>\xcdh\x9a\x1c\x0fLH\x89" +
	"\xf8[93ADH\xef\xd2  \xbd\x03 g\xbc" +
	"\xf8\xb4\xca\xb9\xf6tO<\x9e\x8dy\xa0\x8a\xe7\x95M" +
	"\xf9R\xa0\x17k\xf0\xbc\xb1(^\x0b\xf4G\x86b\x89" +
	"3.Y\x14\x8b\x02\xbd\xc2\xc06\x9eeK\xe2\x83@" +
	"\x7f\xb6x\x10\xe3Y\xb5\xb7W\x04\xfa\x1bC\xb9N\x16" +
	".\x91Z;E\xa4\xbf\x08\xf4:C%\xdc,\x12D" +
	"\xea\xa7\x15\x7f\x08r`\xa8d\"\xbb\xb5\xee\x1bv\xe6" +
	"\xba\xa0\xdf\x01\xe3\xef,\xa7\xcdyo\xa0T6Un" +
	"\x85\x927f\xfc\x1d\xac{\xa1\x8e\xb6Q\xf7\x93\xf8\x85" +
	"\xeaNl\x8b\xdd$A\xb8\xcf\x12T\x9fU\xfe|\xd6" +
	"\x89\x96\xad\xfd \xed\x88\x93\x9e\x8d+\xa7,\xd4\x06\x81" +
	"ndD\x9eoFMX\x18\xb3\xb8@\x0c\x10~\x07" +
	"\x00\x00\xff\xff\x9fS\xf7\xb5"

func init() {
	schemas.Register(schema_f85d2602085656c1,
		0x9f50d21c9d4ce7ef,
		0xb1bdb7d6fb13f1ca,
		0xc3fe25dd82681d64,
		0xd2a8ed7e732926bc)
}
