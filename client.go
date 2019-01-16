package radius

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// Some commonly used attribute IDs
const (
	AttrFramedIPAddress  = 8
	AttrVendorSpecific   = 26
	AttrCallingStationID = 31
	AttrAcctSessionID    = 44
)

// Default CoA ports
const (
	coaPortCisco    = 1700
	coaPortMikrotik = 3799
	coaPortJuniper  = 3799
)

// Some service stuff
var (
	ciscoReauthenticateCommand = "subscriber:command=account-reauthenticate"
	ciscoReauthenticateAVPair  []byte
	juniperServiceActive       = []byte("104 Service active")
)

// RequestParams are parameters specific to an outgoing RADIUS request
type RequestParams struct {
	Secret         []byte
	SrcAddress     *net.UDPAddr
	DstAddressPort *net.UDPAddr
}

// Client that can exchange packets with a RADIUS-enabled host
type Client struct {
	// Local address to use for outgoing connections (can be nil)
	LocalAddr *net.UDPAddr

	// Timeout and retry count
	Timeout time.Duration
	Retries int
}

// RequestResult is a RADIUS request result
type RequestResult struct {
	Success      bool
	Duration     time.Duration
	ErrorCause   ErrorCause
	Error        error
	ErrorString  string
	ResultString string
	Timestamp    time.Time
	AVPairs      []*AVP
}

func init() {
	// Encode the request here for later use
	ciscoReauthenticateAVPair = EncodeAVPairCisco(ciscoReauthenticateCommand)
	juniperServiceActive = []byte(juniperServiceActive)
}

// Exchange sends the packet to the given server address and waits for a
// response.
func (c *Client) Exchange(packet *Packet, dst *net.UDPAddr, src *net.UDPAddr) (reply *Packet, err error) {
	var (
		wire []byte
		conn *net.UDPConn
		n    int
		buf  [maxPacketSize]byte
	)

	if wire, err = packet.Encode(); err != nil {
		return
	}

	// If we weren't provided a src address - try default from context (which may be nil too)
	if src == nil {
		src = c.LocalAddr
	}

	if conn, err = net.DialUDP("udp4", src, dst); err != nil {
		return
	}

	for i := 0; i < c.Retries; i++ {
		conn.SetWriteDeadline(time.Now().Add(c.Timeout))
		if _, err = conn.Write(wire); err != nil {
			break
		}

		conn.SetReadDeadline(time.Now().Add(c.Timeout))
		if n, err = conn.Read(buf[:]); err == nil {
			if reply, err = Parse(buf[:n], packet.Secret, packet.Dictionary); err == nil {
				if !reply.IsAuthentic(packet) {
					err = errors.New("Non-authentic packet")
				}

				break
			}
		}
	}

	conn.Close()
	return
}

// Request send a RADIUS request
func (c *Client) Request(params *RequestParams, requestType Code, attrs ...*Attribute) (result *RequestResult) {
	var (
		reply *Packet
	)

	result = &RequestResult{Timestamp: time.Now()}
	p := New(requestType, params.Secret)
	p.AddAttrs(attrs)

	if reply, result.Error = c.Exchange(p, params.DstAddressPort, params.SrcAddress); result.Error == nil {
		switch reply.Code {
		case CodeDisconnectACK, CodeCoAACK:
			result.Success = true

		case CodeDisconnectNAK, CodeCoANAK:
			if reply.Value("Error-Cause") != nil {
				result.ErrorCause = ErrorCause(reply.Value("Error-Cause").(uint32))
			}

			if result.AVPairs, result.Error = DecodeAVPairs(reply); result.Error != nil {
				result.Error = fmt.Errorf("Got NAK, but unable to parse reply AVPairs: %s", result.Error.Error())
			}

		default:
			result.Error = fmt.Errorf("Unknown reply code: %d", int(reply.Code))
		}
	}

	if result.Success {
		result.ResultString = "ACK"
		return
	}

	if result.Error == nil {
		result.ResultString = "NAK"

		if result.ErrorCause > 0 {
			result.ResultString += " (ErrorCause " + strconv.Itoa(int(result.ErrorCause)) + ")"
		}
	} else {
		if err, ok := result.Error.(net.Error); ok && err.Timeout() {
			result.ResultString = "Timeout"
		} else {
			result.ResultString = "Error"
			result.ErrorString = result.Error.Error()
		}
	}

	return
}

// CiscoRequest is a Cisco request wrapper
func (c *Client) CiscoRequest(Params *RequestParams, RequestType Code, Attrs ...*Attribute) (Result *RequestResult) {
	if Params.DstAddressPort.Port == 0 {
		Params.DstAddressPort.Port = coaPortCisco
	}

	return c.Request(Params, RequestType, Attrs...)
}

// CiscoDisconnect is a Cisco disconnect wrapper
func (c *Client) CiscoDisconnect(Params *RequestParams, CallingStationID string) *RequestResult {
	return c.CiscoRequest(
		Params,
		CodeDisconnectRequest,

		&Attribute{
			Type:  AttrCallingStationID,
			Value: CallingStationID,
		},
	)
}

// CiscoReauthenticate is a Cisco reauthenticate wrapper
func (c *Client) CiscoReauthenticate(Params *RequestParams, CallingStationID string) *RequestResult {
	return c.CiscoRequest(
		Params,
		CodeCoARequest,

		&Attribute{
			Type:  AttrCallingStationID,
			Value: CallingStationID,
		},

		&Attribute{
			Type:  AttrVendorSpecific,
			Value: ciscoReauthenticateAVPair,
		},
	)
}

// JuniperRequest is a Juniper request wrapper
func (c *Client) JuniperRequest(Params *RequestParams, RequestType Code, Attrs ...*Attribute) (Result *RequestResult) {
	if Params.DstAddressPort.Port == 0 {
		Params.DstAddressPort.Port = coaPortJuniper
	}

	return c.Request(Params, RequestType, Attrs...)
}

// JuniperActivateService activates a Juniper service
func (c *Client) JuniperActivateService(Params *RequestParams, AcctSessionID, Service string, Timeout uint32) *RequestResult {
	return c.JuniperRequest(
		Params,
		CodeCoARequest,

		&Attribute{
			Type:  AttrAcctSessionID,
			Value: AcctSessionID,
		},

		&Attribute{
			Type:  AttrVendorSpecific,
			Value: EncodeAVPairJuniperByteTag(AVPJunSvcAct, 1, []byte(Service)),
		},

		&Attribute{
			Type:  AttrVendorSpecific,
			Value: EncodeAVPairJuniperByte(AVPJunSvcTimeout, EncodeJuniperTimeoutTag(Timeout, 1)),
		},
	)
}

// JuniperDeactivateService deactivates a Juniper service
func (c *Client) JuniperDeactivateService(Params *RequestParams, AcctSessionID, Service string) *RequestResult {
	return c.JuniperRequest(
		Params,
		CodeCoARequest,

		&Attribute{
			Type:  AttrAcctSessionID,
			Value: AcctSessionID,
		},

		&Attribute{
			Type:  AttrVendorSpecific,
			Value: EncodeAVPairJuniperByte(AVPJunSvcDeact, []byte(Service)),
		},
	)
}

// JuniperUpdateService Updates a Juniper service
func (c *Client) JuniperUpdateService(Params *RequestParams, AcctSessionID, Service string, Timeout uint32) *RequestResult {
	return c.JuniperRequest(
		Params,
		CodeCoARequest,

		&Attribute{
			Type:  AttrAcctSessionID,
			Value: AcctSessionID,
		},

		&Attribute{
			Type:  AttrVendorSpecific,
			Value: EncodeAVPairJuniperByteTag(AVPJunSvcUpdate, 1, []byte(Service)),
		},

		&Attribute{
			Type:  AttrVendorSpecific,
			Value: EncodeAVPairJuniperByte(AVPJunSvcTimeout, EncodeJuniperTimeoutTag(Timeout, 1)),
		},
	)
}

// JuniperDisconnect disconnects a Juniper session
func (c *Client) JuniperDisconnect(Params *RequestParams, AcctSessionID string) *RequestResult {
	return c.JuniperRequest(
		Params,
		CodeDisconnectRequest,

		&Attribute{
			Type:  AttrAcctSessionID,
			Value: AcctSessionID,
		},
	)
}

// MikrotikRequest is a Mikrotik request wrapper
func (c *Client) MikrotikRequest(Params *RequestParams, RequestType Code, Attrs ...*Attribute) (Result *RequestResult) {
	if Params.DstAddressPort.Port == 0 {
		Params.DstAddressPort.Port = coaPortMikrotik
	}

	return c.Request(Params, RequestType, Attrs...)
}

// MikrotikDisconnect is a Mikrotik disconnect wrapper
func (c *Client) MikrotikDisconnect(Params *RequestParams, ClientIP net.IP) *RequestResult {
	return c.MikrotikRequest(
		Params,
		CodeDisconnectRequest,

		&Attribute{
			Type:  AttrFramedIPAddress,
			Value: ClientIP,
		},
	)
}
