package derp

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"go4.org/mem"
	"golang.org/x/time/rate"
	"tailscale.com/syncs"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// magic is the DERP magic number, sent in the frameServerKey frame
// upon initial connection.
const magic = "DERP🔑" // 8 bytes: 0x44 45 52 50 f0 9f 94 91

// frameType is the one byte frame type at the beginning of the frame
// header.  The second field is a big-endian uint32 describing the
// length of the remaining frame (not including the initial 5 bytes).
type frameType byte

const frameServerKey = frameType(0x01) // 8B magic + 32B public key + (0+ bytes future use)

const frameClientInfo = frameType(0x02) // 32B pub key + 24B nonce + naclbox(json)

const keyLen = 32

// ClientOpt is an option passed to NewClient.
type ClientOpt interface {
	update(*clientOpt)
}

type clientOptFunc func(*clientOpt)

func (f clientOptFunc) update(o *clientOpt) { f(o) }

// clientOpt are the options passed to newClient.
type clientOpt struct {
	MeshKey     string
	ServerPub   key.NodePublic
	CanAckPings bool
	IsProber    bool
}

// ProtocolVersion is bumped whenever there's a wire-incompatible change.
//   - version 1 (zero on wire): consistent box headers, in use by employee dev nodes a bit
//   - version 2: received packets have src addrs in frameRecvPacket at beginning
const ProtocolVersion = 2

type Conn interface {
	io.WriteCloser
	LocalAddr() net.Addr
	// The *Deadline methods follow the semantics of net.Conn.
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// Client is a DERP client.
type Client struct {
	serverKey   key.NodePublic // of the DERP server; not a machine or node key
	privateKey  key.NodePrivate
	publicKey   key.NodePublic // of privateKey
	logf        logger.Logf
	nc          Conn
	br          *bufio.Reader
	meshKey     string
	canAckPings bool
	isProber    bool

	wmu  sync.Mutex // hold while writing to bw
	bw   *bufio.Writer
	rate *rate.Limiter // if non-nil, rate limiter to use

	// Owned by Recv:
	peeked  int                      // bytes to discard on next Recv
	readErr syncs.AtomicValue[error] // sticky (set by Recv)

	clock tstime.Clock
}

func NewClient(privateKey key.NodePrivate, nc Conn, brw *bufio.ReadWriter, logf logger.Logf, opts ...ClientOpt) (*Client, error) {
	var opt clientOpt
	for _, o := range opts {
		if o == nil {
			return nil, errors.New("nil ClientOpt")
		}
		o.update(&opt)
	}
	return newClient(privateKey, nc, brw, logf, opt)
}

func newClient(privateKey key.NodePrivate, nc Conn, brw *bufio.ReadWriter, logf logger.Logf, opt clientOpt) (*Client, error) {
	c := &Client{
		privateKey:  privateKey,
		publicKey:   privateKey.Public(),
		logf:        logf,
		nc:          nc,
		br:          brw.Reader,
		bw:          brw.Writer,
		meshKey:     opt.MeshKey,
		canAckPings: opt.CanAckPings,
		isProber:    opt.IsProber,
		clock:       tstime.StdClock{},
	}
	if opt.ServerPub.IsZero() {
		if err := c.recvServerKey(); err != nil {
			return nil, fmt.Errorf("derp.Client: failed to receive server key: %v", err)
		}
	} else {
		c.serverKey = opt.ServerPub
	}
	if err := c.sendClientKey(); err != nil {
		return nil, fmt.Errorf("derp.Client: failed to send client key: %v", err)
	}
	return c, nil
}

func (c *Client) recvServerKey() error {
	var buf [40]byte
	t, flen, err := readFrame(c.br, 1<<10, buf[:])
	if err == io.ErrShortBuffer {
		// For future-proofing, allow server to send more in its greeting.
		err = nil
	}
	if err != nil {
		return err
	}
	if flen < uint32(len(buf)) || t != frameServerKey || string(buf[:len(magic)]) != magic {
		return errors.New("invalid server greeting")
	}
	c.serverKey = key.NodePublicFromRaw32(mem.B(buf[len(magic):]))
	return nil
}

func (c *Client) sendClientKey() error {
	msg, err := json.Marshal(clientInfo{
		Version:     ProtocolVersion,
		MeshKey:     c.meshKey,
		CanAckPings: c.canAckPings,
		IsProber:    c.isProber,
	})
	if err != nil {
		return err
	}
	msgbox := c.privateKey.SealTo(c.serverKey, msg)

	buf := make([]byte, 0, keyLen+len(msgbox))
	buf = c.publicKey.AppendTo(buf)
	buf = append(buf, msgbox...)
	return writeFrame(c.bw, frameClientInfo, buf)
}


// // Recv reads a message from the DERP server.
// //
// // The returned message may alias memory owned by the Client; it
// // should only be accessed until the next call to Client.
// //
// // Once Recv returns an error, the Client is dead forever.
// func (c *Client) Recv() (m ReceivedMessage, err error) {
// 	return c.recvTimeout(120 * time.Second)
// }


// func (c *Client) recvTimeout(timeout time.Duration) (m ReceivedMessage, err error) {
// 	readErr := c.readErr.Load()
// 	if readErr != nil {
// 		return nil, readErr
// 	}
// 	defer func() {
// 		if err != nil {
// 			err = fmt.Errorf("derp.Recv: %w", err)
// 			c.readErr.Store(err)
// 		}
// 	}()
// 	for {
// 		c.nc.SetReadDeadline(time.Now().Add(timeout))

// 		// Discard any peeked bytes from a previous Recv call.
// 		if c.peeked != 0 {
// 			if n, err := c.br.Discard(c.peeked); err != nil || n != c.peeked {
// 				// Documented to never fail, but might as well check.
// 				return nil, fmt.Errorf("bufio.Reader.Discard(%d bytes): got %v, %v", c.peeked, n, err)
// 			}
// 			c.peeked = 0
// 		}

// 		t, n, err := readFrameHeader(c.br)
// 		if err != nil {
// 			return nil, err
// 		}
// 		if n > 1<<20 {
// 			return nil, fmt.Errorf("unexpectedly large frame of %d bytes returned", n)
// 		}

// 		var b []byte // frame payload (past the 5 byte header)

// 		// If the frame fits in our bufio.Reader buffer, just use it.
// 		// In practice it's 4KB (from derphttp.Client's bufio.NewReader(httpConn)) and
// 		// in practive, WireGuard packets (and thus DERP frames) are under 1.5KB.
// 		// So this is the common path.
// 		if int(n) <= c.br.Size() {
// 			b, err = c.br.Peek(int(n))
// 			c.peeked = int(n)
// 		} else {
// 			// But if for some reason we read a large DERP message (which isn't necessarily
// 			// a WireGuard packet), then just allocate memory for it.
// 			// TODO(bradfitz): use a pool if large frames ever happen in practice.
// 			b = make([]byte, n)
// 			_, err = io.ReadFull(c.br, b)
// 		}
// 		if err != nil {
// 			return nil, err
// 		}

// 		switch t {
// 		default:
// 			continue
// 		case frameServerInfo:
// 			// Server sends this at start-up. Currently unused.
// 			// Just has a JSON message saying "version: 2",
// 			// but the protocol seems extensible enough as-is without
// 			// needing to wait an RTT to discover the version at startup.
// 			// We'd prefer to give the connection to the client (magicsock)
// 			// to start writing as soon as possible.
// 			si, err := c.parseServerInfo(b)
// 			if err != nil {
// 				return nil, fmt.Errorf("invalid server info frame: %v", err)
// 			}
// 			sm := ServerInfoMessage{
// 				TokenBucketBytesPerSecond: si.TokenBucketBytesPerSecond,
// 				TokenBucketBytesBurst:     si.TokenBucketBytesBurst,
// 			}
// 			c.setSendRateLimiter(sm)
// 			return sm, nil
// 		case frameKeepAlive:
// 			// A one-way keep-alive message that doesn't require an acknowledgement.
// 			// This predated framePing/framePong.
// 			return KeepAliveMessage{}, nil
// 		case framePeerGone:
// 			if n < keyLen {
// 				c.logf("[unexpected] dropping short peerGone frame from DERP server")
// 				continue
// 			}
// 			// Backward compatibility for the older peerGone without reason byte
// 			reason := PeerGoneReasonDisconnected
// 			if n > keyLen {
// 				reason = PeerGoneReasonType(b[keyLen])
// 			}
// 			pg := PeerGoneMessage{
// 				Peer:   key.NodePublicFromRaw32(mem.B(b[:keyLen])),
// 				Reason: reason,
// 			}
// 			return pg, nil

// 		case framePeerPresent:
// 			if n < keyLen {
// 				c.logf("[unexpected] dropping short peerPresent frame from DERP server")
// 				continue
// 			}
// 			var msg PeerPresentMessage
// 			msg.Key = key.NodePublicFromRaw32(mem.B(b[:keyLen]))
// 			if n >= keyLen+16+2 {
// 				msg.IPPort = netip.AddrPortFrom(
// 					netip.AddrFrom16([16]byte(b[keyLen:keyLen+16])).Unmap(),
// 					binary.BigEndian.Uint16(b[keyLen+16:keyLen+16+2]),
// 				)
// 			}
// 			return msg, nil

// 		case frameRecvPacket:
// 			var rp ReceivedPacket
// 			if n < keyLen {
// 				c.logf("[unexpected] dropping short packet from DERP server")
// 				continue
// 			}
// 			rp.Source = key.NodePublicFromRaw32(mem.B(b[:keyLen]))
// 			rp.Data = b[keyLen:n]
// 			return rp, nil

// 		case framePing:
// 			var pm PingMessage
// 			if n < 8 {
// 				c.logf("[unexpected] dropping short ping frame")
// 				continue
// 			}
// 			copy(pm[:], b[:])
// 			return pm, nil

// 		case framePong:
// 			var pm PongMessage
// 			if n < 8 {
// 				c.logf("[unexpected] dropping short ping frame")
// 				continue
// 			}
// 			copy(pm[:], b[:])
// 			return pm, nil

// 		case frameHealth:
// 			return HealthMessage{Problem: string(b[:])}, nil

// 		case frameRestarting:
// 			var m ServerRestartingMessage
// 			if n < 8 {
// 				c.logf("[unexpected] dropping short server restarting frame")
// 				continue
// 			}
// 			m.ReconnectIn = time.Duration(binary.BigEndian.Uint32(b[0:4])) * time.Millisecond
// 			m.TryFor = time.Duration(binary.BigEndian.Uint32(b[4:8])) * time.Millisecond
// 			return m, nil
// 		}
// 	}
// }


type clientInfo struct {
	// MeshKey optionally specifies a pre-shared key used by
	// trusted clients.  It's required to subscribe to the
	// connection list & forward packets. It's empty for regular
	// users.
	MeshKey string `json:"meshKey,omitempty"`

	// Version is the DERP protocol version that the client was built with.
	// See the ProtocolVersion const.
	Version int `json:"version,omitempty"`

	// CanAckPings is whether the client declares it's able to ack
	// pings.
	CanAckPings bool

	// IsProber is whether this client is a prober.
	IsProber bool `json:",omitempty"`
}

var bin = binary.BigEndian

func readUint32(br *bufio.Reader) (uint32, error) {
	var b [4]byte
	// Reading a byte at a time is a bit silly,
	// but it causes b not to escape,
	// which more than pays for the silliness.
	for i := range &b {
		c, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		b[i] = c
	}
	return bin.Uint32(b[:]), nil
}

func readFrameHeader(br *bufio.Reader) (t frameType, frameLen uint32, err error) {
	tb, err := br.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	frameLen, err = readUint32(br)
	if err != nil {
		return 0, 0, err
	}
	return frameType(tb), frameLen, nil
}

// readFrame reads a frame header and then reads its payload into
// b[:frameLen].
//
// If the frame header length is greater than maxSize, readFrame returns
// an error after reading the frame header.
//
// If the frame is less than maxSize but greater than len(b), len(b)
// bytes are read, err will be io.ErrShortBuffer, and frameLen and t
// will both be set. That is, callers need to explicitly handle when
// they get more data than expected.
func readFrame(br *bufio.Reader, maxSize uint32, b []byte) (t frameType, frameLen uint32, err error) {
	t, frameLen, err = readFrameHeader(br)
	if err != nil {
		return 0, 0, err
	}
	// if frameLen > maxSize {
	// 	return 0, 0, fmt.Errorf("frame header size %d exceeds reader limit of %d", frameLen, maxSize)
	// }

	n, err := io.ReadFull(br, b[:min(frameLen, uint32(len(b)))])
	if err != nil {
		return 0, 0, err
	}
	remain := frameLen - uint32(n)
	if remain > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(remain)); err != nil {
			return 0, 0, err
		}
		err = io.ErrShortBuffer
	}
	return t, frameLen, err
}

func writeUint32(bw *bufio.Writer, v uint32) error {
	var b [4]byte
	bin.PutUint32(b[:], v)
	// Writing a byte at a time is a bit silly,
	// but it causes b not to escape,
	// which more than pays for the silliness.
	for _, c := range &b {
		err := bw.WriteByte(c)
		if err != nil {
			return err
		}
	}
	return nil
}

func writeFrameHeader(bw *bufio.Writer, t frameType, frameLen uint32) error {
	if err := bw.WriteByte(byte(t)); err != nil {
		return err
	}
	return writeUint32(bw, frameLen)
}

// writeFrame writes a complete frame & flushes it.
func writeFrame(bw *bufio.Writer, t frameType, b []byte) error {
	if len(b) > 10<<20 {
		return errors.New("unreasonably large frame write")
	}
	if err := writeFrameHeader(bw, t, uint32(len(b))); err != nil {
		return err
	}
	if _, err := bw.Write(b); err != nil {
		return err
	}
	return bw.Flush()
}
