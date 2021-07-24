// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: protocols/cmp/keygen/config.proto

package keygen

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	github_com_gogo_protobuf_sortkeys "github.com/gogo/protobuf/sortkeys"
	github_com_taurusgroup_cmp_ecdsa_internal_proto "github.com/taurusgroup/cmp-ecdsa/internal/proto"
	github_com_taurusgroup_cmp_ecdsa_pkg_math_curve "github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	github_com_taurusgroup_cmp_ecdsa_pkg_party "github.com/taurusgroup/cmp-ecdsa/pkg/party"
	io "io"
	math "math"
	math_big "math/big"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// Secret holds secret information for a party
type Secret struct {
	ID github_com_taurusgroup_cmp_ecdsa_pkg_party.ID `protobuf:"bytes,1,opt,name=ID,proto3,casttype=github.com/taurusgroup/cmp-ecdsa/pkg/party.ID" json:"ID,omitempty"`
	// ECDSA is a party's share xᵢ of the secret ECDSA x
	ECDSA *github_com_taurusgroup_cmp_ecdsa_pkg_math_curve.Scalar `protobuf:"bytes,2,opt,name=ECDSA,proto3,customtype=github.com/taurusgroup/cmp-ecdsa/pkg/math/curve.Scalar" json:"ECDSA,omitempty"`
	// P, Q is the primes for N = P*Q used by Paillier and Pedersen
	P *github_com_taurusgroup_cmp_ecdsa_internal_proto.NatMarshaller `protobuf:"bytes,3,opt,name=P,proto3,customtype=github.com/taurusgroup/cmp-ecdsa/internal/proto.NatMarshaller" json:"P,omitempty"`
	Q *github_com_taurusgroup_cmp_ecdsa_internal_proto.NatMarshaller `protobuf:"bytes,4,opt,name=Q,proto3,customtype=github.com/taurusgroup/cmp-ecdsa/internal/proto.NatMarshaller" json:"Q,omitempty"`
}

func (m *Secret) Reset()         { *m = Secret{} }
func (m *Secret) String() string { return proto.CompactTextString(m) }
func (*Secret) ProtoMessage()    {}
func (*Secret) Descriptor() ([]byte, []int) {
	return fileDescriptor_d18db11ba2bb4d59, []int{0}
}
func (m *Secret) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Secret) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *Secret) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Secret.Merge(m, src)
}
func (m *Secret) XXX_Size() int {
	return m.Size()
}
func (m *Secret) XXX_DiscardUnknown() {
	xxx_messageInfo_Secret.DiscardUnknown(m)
}

var xxx_messageInfo_Secret proto.InternalMessageInfo

// Public holds public information for a party
type Public struct {
	// ECDSA public key share
	ECDSA *github_com_taurusgroup_cmp_ecdsa_pkg_math_curve.Point `protobuf:"bytes,1,opt,name=ECDSA,proto3,customtype=github.com/taurusgroup/cmp-ecdsa/pkg/math/curve.Point" json:"ECDSA,omitempty"`
	// N = p•q, p ≡ q ≡ 3 mod 4
	N *math_big.Int `protobuf:"bytes,3,opt,name=N,proto3,casttypewith=math/big.Int;github.com/taurusgroup/cmp-ecdsa/internal/proto.IntCaster" json:"N,omitempty"`
	// S = r² mod N
	S *math_big.Int `protobuf:"bytes,4,opt,name=S,proto3,casttypewith=math/big.Int;github.com/taurusgroup/cmp-ecdsa/internal/proto.IntCaster" json:"S,omitempty"`
	// T = Sˡ mod N
	T *math_big.Int `protobuf:"bytes,5,opt,name=T,proto3,casttypewith=math/big.Int;github.com/taurusgroup/cmp-ecdsa/internal/proto.IntCaster" json:"T,omitempty"`
}

func (m *Public) Reset()         { *m = Public{} }
func (m *Public) String() string { return proto.CompactTextString(m) }
func (*Public) ProtoMessage()    {}
func (*Public) Descriptor() ([]byte, []int) {
	return fileDescriptor_d18db11ba2bb4d59, []int{1}
}
func (m *Public) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Public) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *Public) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Public.Merge(m, src)
}
func (m *Public) XXX_Size() int {
	return m.Size()
}
func (m *Public) XXX_DiscardUnknown() {
	xxx_messageInfo_Public.DiscardUnknown(m)
}

var xxx_messageInfo_Public proto.InternalMessageInfo

// Config represents the SSID after having performed a keygen/refresh operation.
// It represents ssid = (sid, (N₁, s₁, t₁), …, (Nₙ, sₙ, tₙ))
// where sid = (𝔾, t, n, P₁, …, Pₙ).
type Config struct {
	// Threshold is the integer t which defines the maximum number of corruptions tolerated for this config.
	// Threshold + 1 is the minimum number of parties' shares required to reconstruct the secret/sign a message.
	Threshold int32 `protobuf:"varint,1,opt,name=threshold,proto3" json:"threshold,omitempty"`
	// Public maps party.ID to party. It contains all public information associated to a party.
	Public map[github_com_taurusgroup_cmp_ecdsa_pkg_party.ID]*Public `protobuf:"bytes,2,rep,name=public,proto3,castkey=github.com/taurusgroup/cmp-ecdsa/pkg/party.ID" json:"public,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// RID is a 32 byte random identifier generated for this config
	RID     RID `protobuf:"bytes,3,opt,name=RID,proto3,casttype=RID" json:"RID,omitempty"`
	*Secret `protobuf:"bytes,4,opt,name=Secret,proto3,embedded=Secret" json:"Secret,omitempty"`
}

func (m *Config) Reset()         { *m = Config{} }
func (m *Config) String() string { return proto.CompactTextString(m) }
func (*Config) ProtoMessage()    {}
func (*Config) Descriptor() ([]byte, []int) {
	return fileDescriptor_d18db11ba2bb4d59, []int{2}
}
func (m *Config) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Config) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *Config) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Config.Merge(m, src)
}
func (m *Config) XXX_Size() int {
	return m.Size()
}
func (m *Config) XXX_DiscardUnknown() {
	xxx_messageInfo_Config.DiscardUnknown(m)
}

var xxx_messageInfo_Config proto.InternalMessageInfo

func init() {
	proto.RegisterType((*Secret)(nil), "config.Secret")
	proto.RegisterType((*Public)(nil), "config.Public")
	proto.RegisterType((*Config)(nil), "config.Config")
	proto.RegisterMapType((map[github_com_taurusgroup_cmp_ecdsa_pkg_party.ID]*Public)(nil), "config.Config.PublicEntry")
}

func init() { proto.RegisterFile("protocols/cmp/keygen/config.proto", fileDescriptor_d18db11ba2bb4d59) }

var fileDescriptor_d18db11ba2bb4d59 = []byte{
	// 523 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x94, 0xcd, 0x6e, 0xd3, 0x40,
	0x10, 0xc7, 0xb3, 0x4e, 0x63, 0xd4, 0x2d, 0x42, 0x68, 0x4f, 0x26, 0x42, 0x76, 0x88, 0x38, 0xe4,
	0x40, 0x6d, 0xb5, 0x7c, 0x08, 0x8a, 0x38, 0xe4, 0xa3, 0x48, 0x46, 0x22, 0x4d, 0xed, 0x0a, 0x21,
	0x6e, 0x6b, 0x77, 0x6b, 0x5b, 0x71, 0xbc, 0xd6, 0x7a, 0x5d, 0x29, 0x57, 0x9e, 0x80, 0x57, 0xe0,
	0xca, 0x4b, 0x70, 0xed, 0x31, 0xc7, 0x2a, 0x07, 0x17, 0x92, 0x03, 0xef, 0xd0, 0x13, 0xf2, 0xae,
	0x23, 0x72, 0x2b, 0x91, 0x72, 0xb1, 0x3c, 0x33, 0x3b, 0x3f, 0xcd, 0x7f, 0x66, 0x67, 0xe1, 0x93,
	0x94, 0x51, 0x4e, 0x7d, 0x1a, 0x67, 0x96, 0x3f, 0x49, 0xad, 0x31, 0x99, 0x06, 0x24, 0xb1, 0x7c,
	0x9a, 0x5c, 0x44, 0x81, 0x29, 0x62, 0x48, 0x95, 0x56, 0x73, 0x3f, 0x88, 0x78, 0x98, 0x7b, 0xa6,
	0x4f, 0x27, 0x56, 0x40, 0x03, 0x6a, 0x89, 0xb0, 0x97, 0x5f, 0x08, 0x4b, 0x18, 0xe2, 0x4f, 0xa6,
	0xb5, 0x7f, 0x2a, 0x50, 0x75, 0x89, 0xcf, 0x08, 0x47, 0x5d, 0xa8, 0xd8, 0x03, 0x0d, 0xb4, 0x40,
	0x67, 0xb7, 0x77, 0x70, 0x5b, 0x18, 0xeb, 0x24, 0x8e, 0x73, 0x96, 0x67, 0x01, 0xa3, 0x79, 0x5a,
	0x56, 0xb0, 0x4f, 0xfc, 0xf3, 0x0c, 0x5b, 0xe9, 0x38, 0xb0, 0x52, 0xcc, 0xf8, 0xd4, 0xb4, 0x07,
	0x8e, 0x62, 0x0f, 0xd0, 0x08, 0x36, 0x8e, 0xfb, 0x03, 0xb7, 0xab, 0x29, 0x2d, 0xd0, 0xb9, 0xdf,
	0x3b, 0x9a, 0x17, 0xc6, 0xab, 0xff, 0xa2, 0x4c, 0x30, 0x0f, 0x2d, 0x3f, 0x67, 0x97, 0xc4, 0x74,
	0x7d, 0x1c, 0x63, 0xe6, 0x48, 0x10, 0x3a, 0x81, 0x60, 0xa4, 0xd5, 0x05, 0xad, 0x3b, 0x2f, 0x8c,
	0x77, 0x77, 0xd2, 0xa2, 0x84, 0x13, 0x96, 0xe0, 0x58, 0xea, 0x36, 0x87, 0x98, 0x7f, 0xc4, 0x2c,
	0x0b, 0x71, 0x1c, 0x13, 0xe6, 0x80, 0x51, 0x09, 0x3c, 0xd5, 0x76, 0xb6, 0x06, 0x3c, 0x6d, 0xff,
	0x51, 0xa0, 0x3a, 0xca, 0xbd, 0x38, 0xf2, 0xd1, 0xc9, 0x4a, 0x3e, 0x10, 0xfc, 0x37, 0xf3, 0xc2,
	0x78, 0xb9, 0xa9, 0xfc, 0x11, 0x8d, 0x12, 0xbe, 0x52, 0xff, 0x19, 0x82, 0x61, 0xa5, 0xfe, 0xc3,
	0x8f, 0x1b, 0xe3, 0xbd, 0x38, 0xe7, 0x45, 0x81, 0x69, 0x27, 0xfc, 0xed, 0xa6, 0x95, 0xdb, 0x09,
	0xef, 0xe3, 0x8c, 0x97, 0x55, 0x0f, 0x4b, 0xb2, 0x5b, 0xb5, 0x61, 0xab, 0x64, 0xb7, 0x24, 0x9f,
	0x69, 0x8d, 0xed, 0x93, 0xcf, 0xda, 0xdf, 0x15, 0xa8, 0xf6, 0xc5, 0x2d, 0x47, 0x8f, 0xe1, 0x2e,
	0x0f, 0x19, 0xc9, 0x42, 0x1a, 0x9f, 0x8b, 0x6e, 0x37, 0x9c, 0x7f, 0x0e, 0x44, 0xa0, 0x9a, 0x8a,
	0x89, 0x68, 0x4a, 0xab, 0xde, 0xd9, 0x3b, 0x6c, 0x9a, 0xd5, 0xaa, 0xc8, 0x6c, 0x53, 0x8e, 0xeb,
	0x38, 0xe1, 0x6c, 0xda, 0x3b, 0xf8, 0x7a, 0xb3, 0xe9, 0x4d, 0xaf, 0xe0, 0xe8, 0x11, 0xac, 0x3b,
	0xf6, 0xa0, 0x9a, 0xcf, 0xbd, 0xdb, 0xc2, 0x28, 0x4d, 0xa7, 0xfc, 0xa0, 0x67, 0xab, 0xad, 0x12,
	0x3d, 0xde, 0x3b, 0x7c, 0xb0, 0xaa, 0x40, 0x7a, 0x7b, 0x3b, 0xb3, 0xc2, 0x00, 0x4e, 0x75, 0xa6,
	0x69, 0xc3, 0xbd, 0xb5, 0x92, 0xd0, 0x43, 0x58, 0x1f, 0x93, 0xa9, 0xdc, 0x44, 0xa7, 0xfc, 0x45,
	0x4f, 0x61, 0xe3, 0x12, 0xc7, 0x39, 0x11, 0x7b, 0xb5, 0x46, 0x93, 0x59, 0x8e, 0x0c, 0x1e, 0x29,
	0xaf, 0x41, 0xef, 0xd3, 0xd5, 0x6f, 0xbd, 0x76, 0xb5, 0xd0, 0xc1, 0x6c, 0xa1, 0x83, 0xeb, 0x85,
	0x0e, 0x7e, 0x2d, 0x74, 0xf0, 0x6d, 0xa9, 0xd7, 0x66, 0x4b, 0xbd, 0x76, 0xbd, 0xd4, 0x6b, 0x5f,
	0x5e, 0xdc, 0x2d, 0xb6, 0x7a, 0x6c, 0xd6, 0xde, 0x1a, 0x4f, 0x15, 0xce, 0xe7, 0x7f, 0x03, 0x00,
	0x00, 0xff, 0xff, 0xdd, 0xc0, 0x78, 0x5f, 0x8a, 0x04, 0x00, 0x00,
}

func (m *Secret) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Secret) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Secret) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Q != nil {
		{
			size := m.Q.Size()
			i -= size
			if _, err := m.Q.MarshalTo(dAtA[i:]); err != nil {
				return 0, err
			}
			i = encodeVarintConfig(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x22
	}
	if m.P != nil {
		{
			size := m.P.Size()
			i -= size
			if _, err := m.P.MarshalTo(dAtA[i:]); err != nil {
				return 0, err
			}
			i = encodeVarintConfig(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if m.ECDSA != nil {
		{
			size := m.ECDSA.Size()
			i -= size
			if _, err := m.ECDSA.MarshalTo(dAtA[i:]); err != nil {
				return 0, err
			}
			i = encodeVarintConfig(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if len(m.ID) > 0 {
		i -= len(m.ID)
		copy(dAtA[i:], m.ID)
		i = encodeVarintConfig(dAtA, i, uint64(len(m.ID)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *Public) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Public) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Public) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	{
		__caster := &github_com_taurusgroup_cmp_ecdsa_internal_proto.IntCaster{}
		size := __caster.Size(m.T)
		i -= size
		if _, err := __caster.MarshalTo(m.T, dAtA[i:]); err != nil {
			return 0, err
		}
		i = encodeVarintConfig(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x2a
	{
		__caster := &github_com_taurusgroup_cmp_ecdsa_internal_proto.IntCaster{}
		size := __caster.Size(m.S)
		i -= size
		if _, err := __caster.MarshalTo(m.S, dAtA[i:]); err != nil {
			return 0, err
		}
		i = encodeVarintConfig(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x22
	{
		__caster := &github_com_taurusgroup_cmp_ecdsa_internal_proto.IntCaster{}
		size := __caster.Size(m.N)
		i -= size
		if _, err := __caster.MarshalTo(m.N, dAtA[i:]); err != nil {
			return 0, err
		}
		i = encodeVarintConfig(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x1a
	if m.ECDSA != nil {
		{
			size := m.ECDSA.Size()
			i -= size
			if _, err := m.ECDSA.MarshalTo(dAtA[i:]); err != nil {
				return 0, err
			}
			i = encodeVarintConfig(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *Config) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Config) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Config) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Secret != nil {
		{
			size, err := m.Secret.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintConfig(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x22
	}
	if len(m.RID) > 0 {
		i -= len(m.RID)
		copy(dAtA[i:], m.RID)
		i = encodeVarintConfig(dAtA, i, uint64(len(m.RID)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.Public) > 0 {
		keysForPublic := make([]string, 0, len(m.Public))
		for k := range m.Public {
			keysForPublic = append(keysForPublic, string(k))
		}
		github_com_gogo_protobuf_sortkeys.Strings(keysForPublic)
		for iNdEx := len(keysForPublic) - 1; iNdEx >= 0; iNdEx-- {
			v := m.Public[github_com_taurusgroup_cmp_ecdsa_pkg_party.ID(keysForPublic[iNdEx])]
			baseI := i
			if v != nil {
				{
					size, err := v.MarshalToSizedBuffer(dAtA[:i])
					if err != nil {
						return 0, err
					}
					i -= size
					i = encodeVarintConfig(dAtA, i, uint64(size))
				}
				i--
				dAtA[i] = 0x12
			}
			i -= len(keysForPublic[iNdEx])
			copy(dAtA[i:], keysForPublic[iNdEx])
			i = encodeVarintConfig(dAtA, i, uint64(len(keysForPublic[iNdEx])))
			i--
			dAtA[i] = 0xa
			i = encodeVarintConfig(dAtA, i, uint64(baseI-i))
			i--
			dAtA[i] = 0x12
		}
	}
	if m.Threshold != 0 {
		i = encodeVarintConfig(dAtA, i, uint64(m.Threshold))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func encodeVarintConfig(dAtA []byte, offset int, v uint64) int {
	offset -= sovConfig(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Secret) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.ID)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	if m.ECDSA != nil {
		l = m.ECDSA.Size()
		n += 1 + l + sovConfig(uint64(l))
	}
	if m.P != nil {
		l = m.P.Size()
		n += 1 + l + sovConfig(uint64(l))
	}
	if m.Q != nil {
		l = m.Q.Size()
		n += 1 + l + sovConfig(uint64(l))
	}
	return n
}

func (m *Public) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.ECDSA != nil {
		l = m.ECDSA.Size()
		n += 1 + l + sovConfig(uint64(l))
	}
	{
		__caster := &github_com_taurusgroup_cmp_ecdsa_internal_proto.IntCaster{}
		l = __caster.Size(m.N)
		n += 1 + l + sovConfig(uint64(l))
	}
	{
		__caster := &github_com_taurusgroup_cmp_ecdsa_internal_proto.IntCaster{}
		l = __caster.Size(m.S)
		n += 1 + l + sovConfig(uint64(l))
	}
	{
		__caster := &github_com_taurusgroup_cmp_ecdsa_internal_proto.IntCaster{}
		l = __caster.Size(m.T)
		n += 1 + l + sovConfig(uint64(l))
	}
	return n
}

func (m *Config) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Threshold != 0 {
		n += 1 + sovConfig(uint64(m.Threshold))
	}
	if len(m.Public) > 0 {
		for k, v := range m.Public {
			_ = k
			_ = v
			l = 0
			if v != nil {
				l = v.Size()
				l += 1 + sovConfig(uint64(l))
			}
			mapEntrySize := 1 + len(k) + sovConfig(uint64(len(k))) + l
			n += mapEntrySize + 1 + sovConfig(uint64(mapEntrySize))
		}
	}
	l = len(m.RID)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	if m.Secret != nil {
		l = m.Secret.Size()
		n += 1 + l + sovConfig(uint64(l))
	}
	return n
}

func sovConfig(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozConfig(x uint64) (n int) {
	return sovConfig(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Secret) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Secret: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Secret: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ID", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ID = github_com_taurusgroup_cmp_ecdsa_pkg_party.ID(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ECDSA", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			var v github_com_taurusgroup_cmp_ecdsa_pkg_math_curve.Scalar
			m.ECDSA = &v
			if err := m.ECDSA.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field P", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			var v github_com_taurusgroup_cmp_ecdsa_internal_proto.NatMarshaller
			m.P = &v
			if err := m.P.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Q", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			var v github_com_taurusgroup_cmp_ecdsa_internal_proto.NatMarshaller
			m.Q = &v
			if err := m.Q.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConfig(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Public) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Public: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Public: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ECDSA", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			var v github_com_taurusgroup_cmp_ecdsa_pkg_math_curve.Point
			m.ECDSA = &v
			if err := m.ECDSA.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field N", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			{
				__caster := &github_com_taurusgroup_cmp_ecdsa_internal_proto.IntCaster{}
				if tmp, err := __caster.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
					return err
				} else {
					m.N = tmp
				}
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field S", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			{
				__caster := &github_com_taurusgroup_cmp_ecdsa_internal_proto.IntCaster{}
				if tmp, err := __caster.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
					return err
				} else {
					m.S = tmp
				}
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field T", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			{
				__caster := &github_com_taurusgroup_cmp_ecdsa_internal_proto.IntCaster{}
				if tmp, err := __caster.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
					return err
				} else {
					m.T = tmp
				}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConfig(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Config) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Config: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Config: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Threshold", wireType)
			}
			m.Threshold = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Threshold |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Public", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Public == nil {
				m.Public = make(map[github_com_taurusgroup_cmp_ecdsa_pkg_party.ID]*Public)
			}
			var mapkey github_com_taurusgroup_cmp_ecdsa_pkg_party.ID
			var mapvalue *Public
			for iNdEx < postIndex {
				entryPreIndex := iNdEx
				var wire uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowConfig
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					wire |= uint64(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				fieldNum := int32(wire >> 3)
				if fieldNum == 1 {
					var stringLenmapkey uint64
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowConfig
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						stringLenmapkey |= uint64(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapkey := int(stringLenmapkey)
					if intStringLenmapkey < 0 {
						return ErrInvalidLengthConfig
					}
					postStringIndexmapkey := iNdEx + intStringLenmapkey
					if postStringIndexmapkey < 0 {
						return ErrInvalidLengthConfig
					}
					if postStringIndexmapkey > l {
						return io.ErrUnexpectedEOF
					}
					mapkey = github_com_taurusgroup_cmp_ecdsa_pkg_party.ID(dAtA[iNdEx:postStringIndexmapkey])
					iNdEx = postStringIndexmapkey
				} else if fieldNum == 2 {
					var mapmsglen int
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowConfig
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						mapmsglen |= int(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					if mapmsglen < 0 {
						return ErrInvalidLengthConfig
					}
					postmsgIndex := iNdEx + mapmsglen
					if postmsgIndex < 0 {
						return ErrInvalidLengthConfig
					}
					if postmsgIndex > l {
						return io.ErrUnexpectedEOF
					}
					mapvalue = &Public{}
					if err := mapvalue.Unmarshal(dAtA[iNdEx:postmsgIndex]); err != nil {
						return err
					}
					iNdEx = postmsgIndex
				} else {
					iNdEx = entryPreIndex
					skippy, err := skipConfig(dAtA[iNdEx:])
					if err != nil {
						return err
					}
					if (skippy < 0) || (iNdEx+skippy) < 0 {
						return ErrInvalidLengthConfig
					}
					if (iNdEx + skippy) > postIndex {
						return io.ErrUnexpectedEOF
					}
					iNdEx += skippy
				}
			}
			m.Public[github_com_taurusgroup_cmp_ecdsa_pkg_party.ID(mapkey)] = mapvalue
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field RID", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.RID = append(m.RID[:0], dAtA[iNdEx:postIndex]...)
			if m.RID == nil {
				m.RID = []byte{}
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Secret", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Secret == nil {
				m.Secret = &Secret{}
			}
			if err := m.Secret.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConfig(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipConfig(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthConfig
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupConfig
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthConfig
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthConfig        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowConfig          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupConfig = fmt.Errorf("proto: unexpected end of group")
)
