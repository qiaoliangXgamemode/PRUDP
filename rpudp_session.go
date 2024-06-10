package prudp

import (
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// Maximum packet size allowed 1500
	MTULimit = 1500
	/* Accept backlog is full. If we have already queued enough
	 * of warm entries in syn queue, drop request. It is better than
	 * clogging syn queue with openreqs with exponentially increasing
	 * timeout.
	 * Linux Accept queue Default number of 128
	 */
	AcceptBacklog = 128
	// crypto header size
	nonceSize  = 16
	cryptoSize = 4
	// total Header size
	Headercrypto = nonceSize + cryptoSize
)

var (
	err_InvalidOperation = errors.New("invalid operation")
	err_Timeout          = errors.New("timeout")
)

var (
	// to mitigate high-frequency memory allocation for packets, bytes from Transmit Buff
	transmitBuff sync.Pool
)

func init() {
	transmitBuff.New = func() interface{} {
		return make([]byte, MTULimit)
	}
}

const (
	batchSize = 16
)

type batchConn interface {
	WriteBatch(ms []ipv4.Message, flags int) (int, error)
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
}

// ·······································································
// ··Ethernet | IP segment | UDP struct | UDP Data interface | FCS(CRC) ··
// ·······································································
// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬
//
//	UDPinterface
//
// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬
type (
	UDPinterface struct {
		// the underlying packet connection
		conn net.PacketConn
		// Provided to external callers for use
		ownConn bool
		// RPUDP ARQ protocol, Like water do flow ARQ protocol
		rpudp *PRUDP
		// Listener object
		// as client interface or as server interface?
		listener *Listener
		/*
		 * transport encryption block, but protocol not need encryption.
		 * This is just a fast forwarding protocol
		 * The purpose is only fast, and most are handed over to multiplexing solutions
		 */
		block BlockCrypt
		// transport encryption block
		recvbuf []byte
		// remote address
		remote net.Addr
		// read/write deadline
		rd time.Time
		wd time.Time
		// The size of the header attached to the RPUDP frame
		headerSize int
		// Delayed write deadline
		ackNoDelay bool
		writeDelay bool
		dup        int
		// notify session colse die
		Closed  chan struct{}
		dieOnce sync.Once

		// notify Read() / Write() can be called without blocking
		chReadEvent  chan struct{}
		chWriteEvent chan struct{}

		// socket connection error handler
		socketReadError      atomic.Value
		socketWriteError     atomic.Value
		chSocketReadError    chan struct{}
		chSocketWriteError   chan struct{}
		socketReadErrorOnce  sync.Once
		socketWriteErrorOnce sync.Once
		// nonce generator
		nonce Entropy
		// Waiting for packets to be sent over the network
		txqueue         []ipv4.Message
		xconn           batchConn // for x/net
		xconnWriteError error

		mu sync.Mutex
	}
)

// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬
//
//	Listener
//
// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬
// Listener defines a server which will be waiting to accept incoming connections
type Listener struct {
	// block encryption
	block BlockCrypt
	// the underlying packet connection
	conn net.PacketConn
	// true if we created conn internally, false if provided by caller
	OfConn bool

	// all sessions accepted by this Listener
	sessions    map[string]*UDPinterface
	sessionLock sync.RWMutex
	// Listen() backlog
	chAccepts chan *UDPinterface
	// session close queue
	chSessionClosed chan net.Addr

	// notify the listener has closed
	die     chan struct{}
	dieOnce sync.Once

	// socket error handling
	socketReadError     atomic.Value
	chSocketReadError   chan struct{}
	socketReadErrorOnce sync.Once

	// read deadline for Accept()
	rd atomic.Value
}

// Returns func
func (s *UDPinterface) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *UDPinterface) RemoteAddr() net.Addr { return s.remote }

// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬
//
//	Set UDP age func
//
// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬
func (s *UDPinterface) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.rd = t
	s.wd = t
	s.mu.Unlock()
	s.notifyReadEvent()
	s.notifyWriteEvent()
	return nil
}

func (s *UDPinterface) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.rd = t
	s.mu.Unlock()
	s.notifyReadEvent()
	return nil
}

// New Func Session
func newUDPinterface(cookie uint32, dataShards, parityShards int, l *Listener, conn net.PacketConn, ownConn bool, remote net.Addr, block BlockCrypt) *UDPinterface {
	session := new(UDPinterface)
	session.Closed = make(chan struct{})
	session.nonce = new(nonceAES128)
	session.nonce.Init()
	session.chReadEvent = make(chan struct{}, 1)
	session.chWriteEvent = make(chan struct{}, 1)
	session.chSocketReadError = make(chan struct{})
	session.chSocketWriteError = make(chan struct{})
	session.remote = remote
	session.conn = conn
	session.ownConn = ownConn
	session.listener = l
	session.block = block
	session.recvbuf = make([]byte, MTULimit)

	// cast to writebatch conn
	if _, ok := conn.(*net.UDPConn); ok {
		addr, err := net.ResolveUDPAddr("udp", conn.LocalAddr().String())
		if err == nil {
			if addr.IP.To4() != nil {
				session.xconn = ipv4.NewPacketConn(conn)
			} else {
				session.xconn = ipv6.NewPacketConn(conn)
			}
		}
	}

	// calculate additional header size introduced by FEC and encryption
	if session.block != nil {
		session.headerSize += Headercrypto
	}

	session.rpudp = CreatePRUDP(cookie, func(buf []byte, size int) {
		if size >= PRUDP_OVERHEAD+session.headerSize {
			session.output(buf[:size])
		}
	})

	session.rpudp.IsReserveMss(session.headerSize)

	// Start session timer
	SystemTimedSched.Put(session.update, time.Now())

	// currestab := atomic.AddUint64(&DefaultSnmp.CurrEstab, 1)
	// maxconn := atomic.LoadUint64(&DefaultSnmp.MaxConn)
	// if currestab > maxconn {
	// 	atomic.CompareAndSwapUint64(&DefaultSnmp.MaxConn, maxconn, currestab)
	// }

	return session
}

// output | update

// post-processing for sending a packet from kcp core
// steps:
// 2. CRC32 integrity
// 3. Encryption
// 4. TxQueue
func (s *UDPinterface) output(buf []byte) {
	var ecc [][]byte

	// 2&3. crc32 & encryption
	if s.block != nil {
		s.nonce.Fill(buf[:nonceSize])
		checksum := crc32.ChecksumIEEE(buf[Headercrypto:])
		binary.LittleEndian.PutUint32(buf[nonceSize:], checksum)
		s.block.Encrypt(buf, buf)

		for k := range ecc {
			s.nonce.Fill(ecc[k][:nonceSize])
			checksum := crc32.ChecksumIEEE(ecc[k][Headercrypto:])
			binary.LittleEndian.PutUint32(ecc[k][nonceSize:], checksum)
			s.block.Encrypt(ecc[k], ecc[k])
		}
	}

	// 4. TxQueue
	var msg ipv4.Message
	for i := 0; i < s.dup+1; i++ {
		bts := transmitBuff.Get().([]byte)[:len(buf)]
		copy(bts, buf)
		msg.Buffers = [][]byte{bts}
		msg.Addr = s.remote
		s.txqueue = append(s.txqueue, msg)
	}

	for k := range ecc {
		bts := transmitBuff.Get().([]byte)[:len(ecc[k])]
		copy(bts, ecc[k])
		msg.Buffers = [][]byte{bts}
		msg.Addr = s.remote
		s.txqueue = append(s.txqueue, msg)
	}
}

func (s *UDPinterface) update() {
	select {
	case <-s.Closed:
	default:
		s.mu.Lock()
		interval := s.rpudp.flush(false)
		waitsnd := s.rpudp.WaitSnd()
		if waitsnd < int(s.rpudp.send_wind) && waitsnd < int(s.rpudp.remote_wind) {
			s.notifyWriteEvent()
		}
		s.uncork()
		s.mu.Unlock()
		// self-synchronized timed scheduling
		SystemTimedSched.Put(s.update, time.Now().Add(time.Duration(interval)*time.Millisecond))
	}
}

// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬
//
//	Get Session | RTO | SRTT | SRTTVar
//
// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬

// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬
//
//	notify Event [Read | Write] and error Event [Read | Write]
//
// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬

func (s *UDPinterface) notifyReadEvent() {
	select {
	case s.chReadEvent <- struct{}{}:
	default:
	}
}

func (s *UDPinterface) notifyWriteEvent() {
	select {
	case s.chWriteEvent <- struct{}{}:
	default:
	}
}

// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬
//
//	Read / Write Packets data from function
//
// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬
func (s *UDPinterface) Write(b []byte) (n int, err error) { return s.WriteBuffers([][]byte{b}) }

// WriteBuffers write a vector of byte slices to the underlying connection
func (s *UDPinterface) WriteBuffers(v [][]byte) (n int, err error) {
RESET_TIMER:
	var timeout *time.Timer
	var c <-chan time.Time
	if !s.wd.IsZero() {
		delay := time.Until(s.wd)
		timeout = time.NewTimer(delay)
		c = timeout.C
		defer timeout.Stop()
	}

	for {
		select {
		case <-s.chSocketWriteError:
			return 0, s.socketWriteError.Load().(error)
		case <-s.Closed:
			return 0, errors.WithStack(io.ErrClosedPipe)
		default:
		}

		s.mu.Lock()

		// make sure write do not overflow the max sliding window on both side
		waitsnd := s.rpudp.WaitSnd()
		if waitsnd < int(s.rpudp.send_wind) && waitsnd < int(s.rpudp.remote_wind) {
			for _, b := range v {
				n += len(b)
				for {
					if len(b) <= int(s.rpudp.mss) {
						s.rpudp.Send(b)
						break
					} else {
						s.rpudp.Send(b[:s.rpudp.mss])
						b = b[s.rpudp.mss:]
					}
				}
			}

			waitsnd = s.rpudp.WaitSnd()
			if waitsnd >= int(s.rpudp.send_wind) || waitsnd >= int(s.rpudp.remote_wind) || !s.writeDelay {
				s.rpudp.flush(false)
				s.uncork()
			}
			s.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesSent, uint64(n))
			return n, nil
		}

		s.mu.Unlock()

		select {
		case <-s.chWriteEvent:
			if timeout != nil {
				timeout.Stop()
				goto RESET_TIMER
			}
		case <-c:
			return 0, errors.WithStack(errTimeout)
		case <-s.chSocketWriteError:
			return 0, s.socketWriteError.Load().(error)
		case <-s.Closed:
			return 0, errors.WithStack(io.ErrClosedPipe)
		}
	}
}
func Dail() {

}

// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬
//
//	NewConn -> NewRPUDP
//
// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬

func NewConn(raddr string, block BlockCrypt, dataShards, parityShards int, conn net.PacketConn) (*UDPinterface, error) {
	udpaddr, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var session uint32
	binary.Read(rand.Reader, binary.LittleEndian, &session)
	return newUDPinterface(session, dataShards, parityShards, nil, conn, false, udpaddr, block), nil
}

// func NewConn2(raddr string, block BlockCrypt, dataShards, parityShards int, conn net.PacketConn) (*UDPinterface, error) {
// 	udpaddr, err := net.ResolveUDPAddr("udp", raddr)
// 	return newUDPinterface(session, dataShards, parityShards, nil, conn, false, raddr, block), nil
// }
