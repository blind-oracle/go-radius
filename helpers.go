package radius

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// Vendor IDs
const (
	VendCisco     = 9
	VendHuawei    = 2011
	VendJuniper   = 4874
	VendMikrotik  = 14988
	VendAirespace = 14179
)

// Some commond vendor TypeIDs
const (
	AVPJunSvcAct     = 65
	AVPJunSvcDeact   = 66
	AVPJunSvcTimeout = 68
	AVPJunError      = 178
	AVPJunSvcUpdate  = 180
	AVPJunDHCPMac    = 56
	AVPJunDHCPRelay  = 57
	AVPMktAddrList   = 19
)

// AVP is an Attribute-Value pair
type AVP struct {
	VendorID uint32
	TypeID   uint8
	Value    []byte
}

// IsJuniperServiceActive returns true if the Juniper service is active
func (a *AVP) IsJuniperServiceActive() bool {
	return (a.TypeID == AVPJunError) && bytes.Equal(a.Value, juniperServiceActive)
}

// EncodeJuniperTimeoutTag encodes Juniper timeout tag
// Format is Tag (1 byte) + 24bit Integer (3 bytes)
func EncodeJuniperTimeoutTag(timeout uint32, tag uint8) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, timeout)
	b[0] = byte(tag)
	return b
}

// EncodeAVPair encodes AVPair into Vendor-Specific attribute format (string)
func EncodeAVPair(vendorID uint32, typeID uint8, value string) (vsa []byte) {
	return EncodeAVPairByte(vendorID, typeID, []byte(value))
}

// EncodeAVpairTag encodes AVPair into Vendor-Specific attribute format with tag (string)
func EncodeAVpairTag(vendorID uint32, typeID uint8, tag uint8, value string) (vsa []byte) {
	return EncodeAVPairByteTag(vendorID, typeID, tag, []byte(value))
}

// EncodeAVPairByte encodes AVPair into Vendor-Specific attribute format (byte)
func EncodeAVPairByte(vendorID uint32, typeID uint8, value []byte) (vsa []byte) {
	var b bytes.Buffer
	bv := make([]byte, 4)
	binary.BigEndian.PutUint32(bv, vendorID)

	// Vendor-Id(4) + Type-ID(1) + Length(1)
	b.Write(bv)
	b.Write([]byte{byte(typeID), byte(len(value) + 2)})

	// Append attribute value pair
	b.Write(value)

	vsa = b.Bytes()
	return
}

// EncodeAVPairByteTag encodes AVPair into Vendor-Specific attribute format with tag (byte)
func EncodeAVPairByteTag(vendorID uint32, typeID uint8, tag uint8, value []byte) (vsa []byte) {
	var b bytes.Buffer
	bv := make([]byte, 4)
	binary.BigEndian.PutUint32(bv, vendorID)

	// Vendor-Id(4) + Type-ID(1) + Length(1)
	b.Write(bv)
	b.Write([]byte{byte(typeID), byte(len(value) + 3)})

	// Add tag
	b.WriteByte(byte(tag))

	// Append attribute value pair
	b.Write(value)

	vsa = b.Bytes()
	return
}

// DecodeAVPairByte decodes AVP (byte)
func DecodeAVPairByte(vsa []byte) (vendorID uint32, typeID uint8, value []byte, err error) {
	if len(vsa) <= 6 {
		err = fmt.Errorf("Too short VSA: %d bytes", len(vsa))
		return
	}

	vendorID = binary.BigEndian.Uint32([]byte{vsa[0], vsa[1], vsa[2], vsa[3]})
	typeID = uint8(vsa[4])
	value = vsa[6:]
	return
}

// DecodeAVPair decodes AVP (string)
func DecodeAVPair(vsa []byte) (vendorID uint32, typeID uint8, value string, err error) {
	vendorID, typeID, v, err := DecodeAVPairByte(vsa)
	value = string(v)
	return
}

// DecodeAVPairs decodes VSA from the provided packet
func DecodeAVPairs(p *Packet) (avps []*AVP, err error) {
	var (
		VendorID uint32
		TypeID   uint8
		Value    []byte
	)

	for _, vsa := range p.Values("Vendor-Specific") {
		if VendorID, TypeID, Value, err = DecodeAVPairByte(vsa.([]byte)); err != nil {
			avps = nil
			return
		}

		avps = append(avps,
			&AVP{
				VendorID: VendorID,
				TypeID:   TypeID,
				Value:    Value,
			},
		)
	}

	return
}

// Following functions encode different vendor's AVPair into Vendor-Specific attribute format

// EncodeAVPairCisco Cisco
func EncodeAVPairCisco(value string) (vsa []byte) {
	return EncodeAVPair(VendCisco, 1, value)
}

// EncodeAVPairJuniperByte Juniper
func EncodeAVPairJuniperByte(typeID uint8, value []byte) (vsa []byte) {
	return EncodeAVPairByte(VendJuniper, typeID, value)
}

// EncodeAVPairJuniperByteTag Juniper Tagged
func EncodeAVPairJuniperByteTag(typeID uint8, tag uint8, value []byte) (vsa []byte) {
	return EncodeAVPairByteTag(VendJuniper, typeID, tag, value)
}

// EncodeAVPairMikrotikByte Mikrotik
func EncodeAVPairMikrotikByte(typeID uint8, value []byte) (vsa []byte) {
	return EncodeAVPairByte(VendMikrotik, typeID, value)
}

// EncodeAVPairUint32 creates an AVP from uint32
func EncodeAVPairUint32(vendorID uint32, typeID uint8, value uint32) (vsa []byte) {
	bv := make([]byte, 4)
	binary.BigEndian.PutUint32(bv, value)
	return EncodeAVPairByte(vendorID, typeID, bv)
}

// EncodeAVPairInt creates an AVP from int
func EncodeAVPairInt(vendorID uint32, typeID uint8, value int) (vsa []byte) {
	return EncodeAVPairUint32(vendorID, typeID, uint32(value))
}

// Converts IP in net.IP to int
func ipNetToInt(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}

	// Check if it's not IPv4
	if ip.To4() == nil {
		return 0
	}

	return ipByteToInt([]byte(ip.To4()))
}

func ipByteToInt(ip []byte) uint32 {
	var s uint32
	s += uint32(ip[0]) << 24
	s += uint32(ip[1]) << 16
	s += uint32(ip[2]) << 8
	s += uint32(ip[3])
	return s
}

func revUint32Slice(input []uint32) []uint32 {
	if len(input) == 0 {
		return input
	}

	return append(revUint32Slice(input[1:]), input[0])
}

func sortUint32Slice(in []uint32) []uint32 {
	swapped := true

	for swapped {
		swapped = false

		for i := 1; i < len(in); i++ {
			if in[i-1] > in[i] {
				in[i], in[i-1] = in[i-1], in[i]
				swapped = true
			}
		}
	}

	return in
}
