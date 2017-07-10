package radius

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	VEND_CISCO     = 9
	VEND_HUAWEI    = 2011
	VEND_JUNIPER   = 4874
	VEND_MIKROTIK  = 14988
	VEND_AIRESPACE = 14179
	VEND_MT        = 38071
	VEND_MT_FAKE   = 16777215

	AVP_JUN_SVC_ACT     = 65
	AVP_JUN_SVC_DEACT   = 66
	AVP_JUN_SVC_TIMEOUT = 68
	AVP_JUN_ERROR       = 178
	AVP_JUN_SVC_UPDATE  = 180
	AVP_JUN_DHCP_MAC    = 56
	AVP_JUN_DHCP_RELAY  = 57
	AVP_MKT_ADDR_LIST   = 19
)

var (
	VendorMap = map[uint32]int{
		// Cisco
		VEND_CISCO: VEND_CISCO,
		// Cisco also (Airespace)
		VEND_AIRESPACE: VEND_CISCO,
		// Mikrotik
		VEND_MIKROTIK: VEND_MIKROTIK,
		// Huawei
		VEND_HUAWEI: VEND_HUAWEI,
		// Juniper
		VEND_JUNIPER: VEND_JUNIPER,
	}
)

type AVP struct {
	VendorId uint32
	TypeId   uint8
	Value    []byte
}

func (a *AVP) IsJuniperServiceActive() bool {
	return (a.TypeId == AVP_JUN_ERROR) && bytes.Equal(a.Value, juniperServiceActive)
}

// Format is Tag (1 byte) + 24bit Integer (3 bytes)
func EncodeJuniperTimeoutTag(timeout uint32, tag uint8) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, timeout)
	b[0] = byte(tag)
	return b
}

// Encodes AVPair into Vendor-Specific attribute format (string)
func EncodeAVPair(vendor_id uint32, type_id uint8, value string) (vsa []byte) {
	return EncodeAVPairByte(vendor_id, type_id, []byte(value))
}

// Encodes AVPair into Vendor-Specific attribute format with tag (string)
func EncodeAVpairTag(vendor_id uint32, type_id uint8, tag uint8, value string) (vsa []byte) {
	return EncodeAVPairByteTag(vendor_id, type_id, tag, []byte(value))
}

// Encodes AVPair into Vendor-Specific attribute format (byte)
func EncodeAVPairByte(vendor_id uint32, type_id uint8, value []byte) (vsa []byte) {
	var b bytes.Buffer
	bv := make([]byte, 4)
	binary.BigEndian.PutUint32(bv, vendor_id)

	// Vendor-Id(4) + Type-ID(1) + Length(1)
	b.Write(bv)
	b.Write([]byte{byte(type_id), byte(len(value) + 2)})

	// Append attribute value pair
	b.Write(value)

	vsa = b.Bytes()
	return
}

// Encodes AVPair into Vendor-Specific attribute format with tag (byte)
func EncodeAVPairByteTag(vendor_id uint32, type_id uint8, tag uint8, value []byte) (vsa []byte) {
	var b bytes.Buffer
	bv := make([]byte, 4)
	binary.BigEndian.PutUint32(bv, vendor_id)

	// Vendor-Id(4) + Type-ID(1) + Length(1)
	b.Write(bv)
	b.Write([]byte{byte(type_id), byte(len(value) + 3)})

	// Add tag
	b.WriteByte(byte(tag))

	// Append attribute value pair
	b.Write(value)

	vsa = b.Bytes()
	return
}

// Decodes VSA (byte)
func DecodeAVPairByte(vsa []byte) (vendor_id uint32, type_id uint8, value []byte, err error) {
	if len(vsa) <= 6 {
		err = fmt.Errorf("Too short VSA: %d bytes", len(vsa))
		return
	}

	vendor_id = binary.BigEndian.Uint32([]byte{vsa[0], vsa[1], vsa[2], vsa[3]})
	type_id = uint8(vsa[4])
	value = vsa[6:]
	return
}

// Decodes VSA (string)
func DecodeAVPair(vsa []byte) (vendor_id uint32, type_id uint8, value string, err error) {
	vendor_id, type_id, value_b, err := DecodeAVPairByte(vsa)
	value = string(value_b)
	return
}

func DecodeAVPairs(p *Packet) (avps []*AVP, err error) {
	var (
		VendorId uint32
		TypeId   uint8
		Value    []byte
	)

	for _, vsa := range p.Values("Vendor-Specific") {
		if VendorId, TypeId, Value, err = DecodeAVPairByte(vsa.([]byte)); err != nil {
			avps = nil
			return
		} else {
			avps = append(avps,
				&AVP{
					VendorId: VendorId,
					TypeId:   TypeId,
					Value:    Value,
				},
			)
		}
	}

	return
}

// Following functions encode different vendor's AVPair into Vendor-Specific attribute format

// Cisco
func EncodeAVPairCisco(value string) (vsa []byte) {
	return EncodeAVPair(VEND_CISCO, 1, value)
}

// Juniper
func EncodeAVPairJuniperByte(type_id uint8, value []byte) (vsa []byte) {
	return EncodeAVPairByte(VEND_JUNIPER, type_id, value)
}

func EncodeAVPairJuniperByteTag(type_id uint8, tag uint8, value []byte) (vsa []byte) {
	return EncodeAVPairByteTag(VEND_JUNIPER, type_id, tag, value)
}

// Mikrotik
func EncodeAVPairMikrotikByte(type_id uint8, value []byte) (vsa []byte) {
	return EncodeAVPairByte(VEND_MIKROTIK, type_id, value)
}

// MaximaTelecom
func EncodeAVPairMT(value string) (vsa []byte) {
	return EncodeAVPair(VEND_MT_FAKE, 1, value)
}

func EncodeAVPairUint32(vendor_id uint32, type_id uint8, value uint32) (vsa []byte) {
	bv := make([]byte, 4)
	binary.BigEndian.PutUint32(bv, value)
	return EncodeAVPairByte(vendor_id, type_id, bv)
}

func EncodeAVPairInt(vendor_id uint32, type_id uint8, value int) (vsa []byte) {
	return EncodeAVPairUint32(vendor_id, type_id, uint32(value))
}
