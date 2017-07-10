package radius

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

const (
	RAD_ATTR_FRAMED_IP_ADDRESS  = 8
	RAD_ATTR_VENDOR_SPECIFIC    = 26
	RAD_ATTR_CALLING_STATION_ID = 31
	RAD_ATTR_ACCT_SESSION_ID    = 44

	COA_PORT_CISCO    = 1700
	COA_PORT_MIKROTIK = 3799
	COA_PORT_JUNIPER  = 3799
	COA_PORT_IPOE     = 3799

	CISCO_REAUTHENTICATE_COMMAND = "subscriber:command=account-reauthenticate"
	JUNIPER_SERVICE_ACTIVE       = "104 Service active"

	REQ_TYPE_DISCONNECT = 1
	REQ_TYPE_AUTHORIZE  = 2
)

var (
	ciscoReauthenticateAVPair []byte
	juniperServiceActive      []byte
)

// Parameters specific to an outgoing RADIUS request
type RADIUSParams struct {
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
	ciscoReauthenticateAVPair = EncodeAVPairCisco(CISCO_REAUTHENTICATE_COMMAND)
	juniperServiceActive = []byte(JUNIPER_SERVICE_ACTIVE)
}

// Exchange sends the packet to the given server address and waits for a
// response. nil and an error is returned upon failure.
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

func (c *Client) Request(Params *RADIUSParams, RequestType Code, Attrs ...*Attribute) (Result *RequestResult) {
	var (
		reply *Packet
	)

	Result = &RequestResult{Timestamp: time.Now()}
	p := New(RequestType, Params.Secret)
	p.AddAttrs(Attrs)

	if reply, Result.Error = c.Exchange(p, Params.DstAddressPort, Params.SrcAddress); Result.Error == nil {
		switch reply.Code {
		case CodeDisconnectACK, CodeCoAACK:
			Result.Success = true

		case CodeDisconnectNAK, CodeCoANAK:
			if reply.Value("Error-Cause") != nil {
				Result.ErrorCause = ErrorCause(reply.Value("Error-Cause").(uint32))
			}

			if Result.AVPairs, Result.Error = DecodeAVPairs(reply); Result.Error != nil {
				Result.Error = fmt.Errorf("Got NAK, but unable to parse reply AVPairs: %s", Result.Error.Error())
			}

		default:
			Result.Error = fmt.Errorf("Unknown reply code: %d", int(reply.Code))
		}
	}

	if Result.Success {
		Result.ResultString = "ACK"
	} else {
		if Result.Error == nil {
			Result.ResultString = "NAK"

			if Result.ErrorCause > 0 {
				Result.ResultString += " (ErrorCause " + strconv.Itoa(int(Result.ErrorCause)) + ")"
			}
		} else {
			if err, ok := Result.Error.(net.Error); ok && err.Timeout() {
				Result.ResultString = "Timeout"
			} else {
				Result.ResultString = "Error"
				Result.ErrorString = Result.Error.Error()
			}
		}
	}

	return
}

// IPoE request wrapper
func (c *Client) IPoERequest(Params *RADIUSParams, RequestType Code, Attrs ...*Attribute) (Result *RequestResult) {
	if Params.DstAddressPort.Port == 0 {
		Params.DstAddressPort.Port = COA_PORT_IPOE
	}

	return c.Request(Params, RequestType, Attrs...)
}

// IPoE disconnect wrapper
func (c *Client) IPoEDisconnect(Params *RADIUSParams, CallingStationId string) *RequestResult {
	return c.IPoERequest(
		Params,
		CodeDisconnectRequest,

		&Attribute{
			Type:  RAD_ATTR_CALLING_STATION_ID,
			Value: CallingStationId,
		},
	)
}

// Cisco request wrapper
func (c *Client) CiscoRequest(Params *RADIUSParams, RequestType Code, Attrs ...*Attribute) (Result *RequestResult) {
	if Params.DstAddressPort.Port == 0 {
		Params.DstAddressPort.Port = COA_PORT_CISCO
	}

	return c.Request(Params, RequestType, Attrs...)
}

// Cisco disconnect wrapper
func (c *Client) CiscoDisconnect(Params *RADIUSParams, CallingStationId string) *RequestResult {
	return c.CiscoRequest(
		Params,
		CodeDisconnectRequest,

		&Attribute{
			Type:  RAD_ATTR_CALLING_STATION_ID,
			Value: CallingStationId,
		},
	)
}

// Cisco reauthenticate wrapper
func (c *Client) CiscoReauthenticate(Params *RADIUSParams, CallingStationId string) *RequestResult {
	return c.CiscoRequest(
		Params,
		CodeCoARequest,

		&Attribute{
			Type:  RAD_ATTR_CALLING_STATION_ID,
			Value: CallingStationId,
		},

		&Attribute{
			Type:  RAD_ATTR_VENDOR_SPECIFIC,
			Value: ciscoReauthenticateAVPair,
		},
	)
}

// Juniper request wrapper
func (c *Client) JuniperRequest(Params *RADIUSParams, RequestType Code, Attrs ...*Attribute) (Result *RequestResult) {
	if Params.DstAddressPort.Port == 0 {
		Params.DstAddressPort.Port = COA_PORT_JUNIPER
	}

	return c.Request(Params, RequestType, Attrs...)
}

// Activates a Juniper service
func (c *Client) JuniperActivateService(Params *RADIUSParams, AcctSessionId, Service string, Timeout uint32) *RequestResult {
	return c.JuniperRequest(
		Params,
		CodeCoARequest,

		&Attribute{
			Type:  RAD_ATTR_ACCT_SESSION_ID,
			Value: AcctSessionId,
		},

		&Attribute{
			Type:  RAD_ATTR_VENDOR_SPECIFIC,
			Value: EncodeAVPairJuniperByteTag(AVP_JUN_SVC_ACT, 1, []byte(Service)),
		},

		&Attribute{
			Type:  RAD_ATTR_VENDOR_SPECIFIC,
			Value: EncodeAVPairJuniperByte(AVP_JUN_SVC_TIMEOUT, EncodeJuniperTimeoutTag(Timeout, 1)),
		},
	)
}

// Deactivates a Juniper service
func (c *Client) JuniperDeactivateService(Params *RADIUSParams, AcctSessionId, Service string) *RequestResult {
	return c.JuniperRequest(
		Params,
		CodeCoARequest,

		&Attribute{
			Type:  RAD_ATTR_ACCT_SESSION_ID,
			Value: AcctSessionId,
		},

		&Attribute{
			Type:  RAD_ATTR_VENDOR_SPECIFIC,
			Value: EncodeAVPairJuniperByte(AVP_JUN_SVC_DEACT, []byte(Service)),
		},
	)
}

// Update a Juniper service
func (c *Client) JuniperUpdateService(Params *RADIUSParams, AcctSessionId, Service string, Timeout uint32) *RequestResult {
	return c.JuniperRequest(
		Params,
		CodeCoARequest,

		&Attribute{
			Type:  RAD_ATTR_ACCT_SESSION_ID,
			Value: AcctSessionId,
		},

		&Attribute{
			Type:  RAD_ATTR_VENDOR_SPECIFIC,
			Value: EncodeAVPairJuniperByteTag(AVP_JUN_SVC_UPDATE, 1, []byte(Service)),
		},

		&Attribute{
			Type:  RAD_ATTR_VENDOR_SPECIFIC,
			Value: EncodeAVPairJuniperByte(AVP_JUN_SVC_TIMEOUT, EncodeJuniperTimeoutTag(Timeout, 1)),
		},
	)
}

// Disconnect a Juniper session
func (c *Client) JuniperDisconnect(Params *RADIUSParams, AcctSessionId string) *RequestResult {
	return c.JuniperRequest(
		Params,
		CodeDisconnectRequest,

		&Attribute{
			Type:  RAD_ATTR_ACCT_SESSION_ID,
			Value: AcctSessionId,
		},
	)
}

// Mikrotik request wrapper
func (c *Client) MikrotikRequest(Params *RADIUSParams, RequestType Code, Attrs ...*Attribute) (Result *RequestResult) {
	if Params.DstAddressPort.Port == 0 {
		Params.DstAddressPort.Port = COA_PORT_MIKROTIK
	}

	return c.Request(Params, RequestType, Attrs...)
}

// Mikrotik disconnect wrapper
func (c *Client) MikrotikDisconnect(Params *RADIUSParams, ClientIP net.IP) *RequestResult {
	return c.MikrotikRequest(
		Params,
		CodeDisconnectRequest,

		&Attribute{
			Type:  RAD_ATTR_FRAMED_IP_ADDRESS,
			Value: ClientIP,
		},
	)
}
