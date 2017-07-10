package radius

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	aux "github.com/blind-oracle/go-aux"

	"golang.org/x/time/rate"
)

// Handler is a value that can handle a server's RADIUS packet event.
type Handler interface {
	ServeRadius(w ResponseWriter, p *Packet)
}

// HandlerFunc is a wrapper that allows ordinary functions to be used as a
// handler.
type HandlerFunc func(w ResponseWriter, p *Packet)

// ServeRadius calls h(w, p).
func (h HandlerFunc) ServeRadius(w ResponseWriter, p *Packet) {
	h(w, p)
}

// ResponseWriter is used by Handler when replying to a RADIUS packet.
type ResponseWriter interface {
	// LocalAddr returns the address of the local server that accepted the
	// packet.
	LocalAddr() net.Addr

	// RemoteAddr returns the address of the remote client that sent to packet.
	RemoteAddr() net.Addr

	// Write sends a packet to the sender.
	Write(packet *Packet) error

	// AccountingACK sends an Accounting-Response packet to the sender that includes
	// the given attributes. (c) Novgorodov
	AccountingACK(attributes ...*Attribute) error

	// AccessAccept sends an Access-Accept packet to the sender that includes
	// the given attributes.
	AccessAccept(attributes ...*Attribute) error

	// AccessAccept sends an Access-Reject packet to the sender that includes
	// the given attributes.
	AccessReject(attributes ...*Attribute) error

	// AccessAccept sends an Access-Challenge packet to the sender that includes
	// the given attributes.
	AccessChallenge(attributes ...*Attribute) error

	SetReplicationDestinations([]*net.UDPAddr)
	SetReplyReplication(bool)
}

type responseWriter struct {
	// listener that received the packet
	conn *net.UDPConn

	// where the packet came from
	addr *net.UDPAddr

	// original packet
	packet *Packet

	// original packet (raw)
	raw []byte

	// Where to replicate request packet specifically to this transaction
	replicateToUDPAddr []net.UDPAddr
	replicateReplies   bool
}

func (r *responseWriter) LocalAddr() net.Addr {
	return r.conn.LocalAddr()
}

func (r *responseWriter) RemoteAddr() net.Addr {
	return r.addr
}

func (r *responseWriter) accessRespond(code Code, attributes ...*Attribute) error {
	packet := Packet{
		Code:          code,
		Identifier:    r.packet.Identifier,
		Authenticator: r.packet.Authenticator,
		Secret:        r.packet.Secret,
		Dictionary:    r.packet.Dictionary,
		Attributes:    attributes,
	}

	return r.Write(&packet)
}

// (c) Novgorodov
func (r *responseWriter) AccountingACK(attributes ...*Attribute) error {
	return r.accessRespond(CodeAccountingResponse, attributes...)
}

func (r *responseWriter) AccessAccept(attributes ...*Attribute) error {
	// TOOD: do not send if packet was not Access-Request
	return r.accessRespond(CodeAccessAccept, attributes...)
}

func (r *responseWriter) AccessReject(attributes ...*Attribute) error {
	// TOOD: do not send if packet was not Access-Request
	return r.accessRespond(CodeAccessReject, attributes...)
}

func (r *responseWriter) AccessChallenge(attributes ...*Attribute) error {
	// TOOD: do not send if packet was not Access-Request
	return r.accessRespond(CodeAccessChallenge, attributes...)
}

func (r *responseWriter) Write(packet *Packet) error {
	raw, err := packet.Encode()
	if err != nil {
		return err
	}

	if _, err := r.conn.WriteToUDP(raw, r.addr); err != nil {
		return err
	}

	// Replicate request and reply to configured destinations
	if len(r.replicateToUDPAddr) == 0 {
		return nil
	}

	for _, rdest := range r.replicateToUDPAddr {
		// Errors are not checked intentionally
		r.conn.WriteToUDP(r.raw, &rdest)

		if r.replicateReplies {
			r.conn.WriteToUDP(raw, &rdest)
		}
	}

	return nil
}

func (r *responseWriter) SetReplicationDestinations(rdest []*net.UDPAddr) {
	for _, rd := range rdest {
		r.replicateToUDPAddr = append(r.replicateToUDPAddr, *rd)
	}
}

func (r *responseWriter) SetReplyReplication(state bool) {
	r.replicateReplies = state
}

type RadClient struct {
	Net    uint32
	Mask   uint32
	Secret []byte
}

// Server is a server that listens for and handles RADIUS packets.
type Server struct {
	// Address to bind the server on. If empty, the address defaults to ":1812".
	Addr string

	// Network of the server. Valid values are "udp", "udp4", "udp6". If empty,
	// the network defaults to "udp".
	Network string

	// The shared secret between the client and server.
	Secret []byte

	// Slice of addresses where to replicate requests
	ReplicateTo        []string
	ReplicateReplies   bool
	replicateToUDPAddr []*net.UDPAddr

	// Client->Secret mapping
	ClientsSecrets map[string]string
	clientsMap     map[uint32]*RadClient
	clientsMasks   []uint32

	// Ratelimit
	RateLimiter         *rate.Limiter
	RateLimiterCtx      context.Context
	MaxPendingRequests  uint32
	PendingRequests     uint32
	PendingRequestsMtx  sync.Mutex
	PendingRequestsCond *sync.Cond

	// Buffer
	BufferSize int

	// Dictionary used when decoding incoming packets.
	Dictionary *Dictionary

	// The packet handler that handles incoming, valid packets.
	Handler Handler

	// Listener
	listener *net.UDPConn
}

// Parse clients map (c) Novgorodov
func parseClientsMap(ClientsMapIn map[string]string) (ClientsMapOut map[uint32]*RadClient, MasksOut []uint32, err error) {
	var subnet *net.IPNet

	if ClientsMapIn == nil {
		err = errors.New("Clients map is nil")
		return
	}

	ClientsMapOut = make(map[uint32]*RadClient)
	MasksTmp := make(map[uint32]bool)

	for k, v := range ClientsMapIn {
		if _, subnet, err = net.ParseCIDR(k); err != nil {
			return
		}

		x := aux.IPNetToInt(subnet.IP)
		ClientsMapOut[x] = &RadClient{
			Net:    x,
			Mask:   aux.IPByteToInt([]byte(subnet.Mask)),
			Secret: []byte(v),
		}

		MasksTmp[ClientsMapOut[x].Mask] = true
	}

	// Remember distinct masks and sort them in descending order
	// Needed to prefer shorter prefixes (/32..) over long (/8...) when iterating array
	for k, _ := range MasksTmp {
		MasksOut = append(MasksOut, k)
	}

	MasksOut = aux.ReverseUint32Slice(aux.SortUint32Slice(MasksOut))
	return
}

// ListenAndServe starts a RADIUS server on the address given in s.
func (s *Server) ListenAndServe() (err error) {
	if s.listener != nil {
		return errors.New("radius: server already started")
	}

	if s.Handler == nil {
		return errors.New("radius: nil Handler")
	}

	if s.ClientsSecrets != nil {
		if s.clientsMap, s.clientsMasks, err = parseClientsMap(s.ClientsSecrets); err != nil {
			return
		}
	}

	if s.MaxPendingRequests > 0 {
		s.PendingRequestsCond = sync.NewCond(&s.PendingRequestsMtx)
	}

	addrStr := ":1812"
	if s.Addr != "" {
		addrStr = s.Addr
	}

	network := "udp"
	if s.Network != "" {
		network = s.Network
	}

	addr, err := net.ResolveUDPAddr(network, addrStr)
	if err != nil {
		return err
	}

	s.listener, err = net.ListenUDP(network, addr)
	if err != nil {
		return err
	}

	if s.BufferSize > 0 {
		s.listener.SetReadBuffer(s.BufferSize)
		s.listener.SetWriteBuffer(s.BufferSize)
	}

	// Parse replication destinations
	for _, rdest := range s.ReplicateTo {
		if uaddr, err := net.ResolveUDPAddr("udp4", rdest); err != nil {
			return errors.New("Unable to parse UDPAddr: " + rdest)
		} else {
			s.replicateToUDPAddr = append(s.replicateToUDPAddr, uaddr)
		}
	}

	for {
		// Ratelimit incoming requests
		if s.RateLimiter != nil {
			s.RateLimiter.Wait(s.RateLimiterCtx)
		}

		// Check if we're over max allowed requests
		if s.MaxPendingRequests > 0 {
			s.PendingRequestsMtx.Lock()
			for atomic.LoadUint32(&s.PendingRequests) >= s.MaxPendingRequests {
				// If we are then wait until we are not :)
				s.PendingRequestsCond.Wait()
			}
			s.PendingRequestsMtx.Unlock()
		}

		buff := make([]byte, maxPacketSize)
		n, remoteAddr, err := s.listener.ReadFromUDP(buff)
		if err != nil && !err.(*net.OpError).Temporary() {
			break
		}

		if n == 0 {
			continue
		}

		if s.MaxPendingRequests > 0 {
			atomic.AddUint32(&s.PendingRequests, 1)
		}

		buff = buff[:n]
		go func(conn *net.UDPConn, buff []byte, remoteAddr *net.UDPAddr) {
			var (
				packet *Packet
				ip     uint32
				secret []byte
				err    error
			)

			// Set default secret
			secret = s.Secret

			// Check if client is defined, use default secret otherwise
			if s.clientsMap != nil {
				ip = aux.IPNetToInt(remoteAddr.IP)
				for _, m := range s.clientsMasks {
					if client, ok := s.clientsMap[ip&m]; ok {
						secret = client.Secret
						break
					}
				}
			}

			if packet, err = Parse(buff, secret, s.Dictionary); err != nil {
				return
			}

			response := responseWriter{
				conn:   conn,
				addr:   remoteAddr,
				packet: packet,
				raw:    buff,
			}

			if s.ReplicateReplies {
				response.replicateReplies = true
			}

			s.Handler.ServeRadius(&response, packet)

			// Replicate request to globally configured destinations after work is complete
			if len(s.replicateToUDPAddr) > 0 {
				for _, rdest := range s.replicateToUDPAddr {
					// Errors are not checked intentionally
					conn.WriteToUDP(buff, rdest)
				}
			}

			// Decrement the counter and broadcast about it
			if s.MaxPendingRequests > 0 {
				s.PendingRequestsMtx.Lock()
				atomic.AddUint32(&s.PendingRequests, ^uint32(0))
				s.PendingRequestsCond.Broadcast()
				s.PendingRequestsMtx.Unlock()
			}
		}(s.listener, buff, remoteAddr)
	}

	// TODO: only return nil if s.Close was called
	s.listener = nil
	return nil
}

// Close stops listening for packets. Any packet that is currently being
// handled will not be able to respond to the sender.
func (s *Server) Close() error {
	if s.listener == nil {
		return nil
	}
	return s.listener.Close()
}
