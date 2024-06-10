package prudp

import (
	"sync/atomic"
	"time"
)

const (
	PRUDP_RTO_NDL     = 30  // no delay min rto
	PRUDP_RTO_MIN     = 100 // normal min rto
	PRUDP_RTO_DEF     = 200
	PRUDP_RTO_MAX     = 60000
	PRUDP_CMD_PUSH    = 81 // cmd: push data
	PRUDP_CMD_ACK     = 82 // cmd: ack
	PRUDP_CMD_WASK    = 83 // cmd: window probe (ask)
	PRUDP_CMD_WINS    = 84 // cmd: window size (tell)
	PRUDP_ASK_SEND    = 1  // need to send PRUDP_CMD_WASK
	PRUDP_ASK_TELL    = 2  // need to send PRUDP_CMD_WINS
	PRUDP_WND_SND     = 32
	PRUDP_WND_RCV     = 32
	PRUDP_MTU_DEF     = 1400
	PRUDP_ACK_FAST    = 3
	PRUDP_INTERVAL    = 100
	PRUDP_OVERHEAD    = 24
	PRUDP_DEADLINK    = 20
	PRUDP_THRESH_INIT = 2
	PRUDP_THRESH_MIN  = 2
	PRUDP_PROBE_INIT  = 7000   // 7 secs to probe window size
	PRUDP_PROBE_LIMIT = 120000 // up to 120 secs to probe window
	PRUDP_SN_OFFSET   = 12
)

// RUDP segment
type segment struct {
	session  uint32 // number
	cmd      uint8  // command
	frg      uint8  // fragment MSS segment
	wnd      uint16 // window size
	ts       uint32 // timestamp
	sn       uint32 // sequence number
	una      uint32 // unacknowledged
	rto      uint32 // retransmission timeout
	xmit     uint32 // transmit
	resendts uint32 // resend timestamp
	fastack  uint32 // fast acknowledge
	acked    uint32 // mark if the seg has acked
	data     []byte // data textcont
}

// output_callback is a prototype which ought capture conn and call conn.Write
type output_callback func(buf []byte, size int)

// to be send ACK, includ ts and sn.
// ts -> Timestamp
// sn -> Sequence Number
type ackItem struct {
	sn uint32
	ts uint32
}

// single RPUDP connection

type PRUDP struct {
	MTU, mss, state                                  uint32
	session                                          uint32
	send_una, send_next, recv_next                   uint32
	ssthresh                                         uint32
	net_RTTvar, net_RTTs                             int32
	net_rto, net_Minrto                              uint32
	send_wind, revc_wind, remote_wind, c_wind, probe uint32
	interval, ts_flush                               uint32
	nodelay, updated                                 uint32
	ts_probe, probe_wait                             uint32
	dead_link, incr                                  uint32
	fastReSend                                       int32
	flowCONwind, stream                              int32

	// queue for index point
	// buf save or delete data to network, can speak write and read.
	send_queue []segment
	recv_queue []segment
	send_buf   []segment
	recv_buf   []segment

	// to be send ACK, includ ts and sn.
	// ts -> Timestamp
	// sn -> Sequence Number
	acklist []ackItem

	// interim buffer, but Doesn't seem to make much sense.
	buffer   []byte
	reserved int
	output   output_callback
}

// Segment Struct Func TO
// encode a segment into buffer
func (seg *segment) encode(ptr []byte) []byte {
	ptr = prudp_encode32u(ptr, seg.session)
	ptr = prudp_encode8u(ptr, seg.cmd)
	ptr = prudp_encode8u(ptr, seg.frg)
	ptr = prudp_encode16u(ptr, seg.wnd)
	ptr = prudp_encode32u(ptr, seg.ts)
	ptr = prudp_encode32u(ptr, seg.sn)
	ptr = prudp_encode32u(ptr, seg.una)
	ptr = prudp_encode32u(ptr, uint32(len(seg.data)))
	atomic.AddUint64(&DefaultSnmp.OutSegs, 1)
	return ptr
}

// unpack a segment into buffer
func (seg *segment) decode(data []byte, seesion uint32, cmd uint8, frg uint8, wnd uint16, ts uint32, sn uint32, length uint32, una uint32, conv uint32) []byte {
	data = prudp_decode32u(data, &seesion)
	data = prudp_decode8u(data, &cmd)
	data = prudp_decode8u(data, &frg)
	data = prudp_decode16u(data, &wnd)
	data = prudp_decode32u(data, &ts)
	data = prudp_decode32u(data, &sn)
	data = prudp_decode32u(data, &una)
	data = prudp_decode32u(data, &length)
	atomic.AddUint64(&DefaultSnmp.OutSegs, 1)
	return data
}

func _imin_(a, b uint32) uint32 {
	if a <= b {
		return a
	}
	return b
}

func _imax_(a, b uint32) uint32 {
	if a >= b {
		return a
	}
	return b
}

func _ibound_(lower, middle, upper uint32) uint32 {
	return _imin_(_imax_(lower, middle), upper)
}

func _itimediff(later, earlier uint32) int32 {
	return (int32)(later - earlier)
}

// monotonic reference time point
var refTime time.Time = time.Now()

// currentMs returns current elapsed monotonic milliseconds since program startup
func currentMs() uint32 { return uint32(time.Since(refTime) / time.Millisecond) }

// CreatePRUDP create a new PRUDP state machine
//
// 'conv' must be equal in the connection peers, or else data will be silently rejected.
//
// 'output' function will be called whenever these is data to be sent on wire.
func CreatePRUDP(session uint32, output output_callback) *PRUDP {
	rpudp := new(PRUDP)
	rpudp.session = session
	rpudp.send_wind = PRUDP_WND_SND
	rpudp.revc_wind = PRUDP_WND_RCV
	rpudp.remote_wind = PRUDP_WND_RCV
	rpudp.MTU = PRUDP_MTU_DEF
	rpudp.mss = rpudp.MTU - PRUDP_OVERHEAD
	rpudp.buffer = make([]byte, rpudp.MTU)
	rpudp.net_rto = PRUDP_RTO_DEF
	rpudp.net_Minrto = PRUDP_RTO_MIN
	rpudp.interval = PRUDP_INTERVAL
	rpudp.ts_flush = PRUDP_INTERVAL
	rpudp.ssthresh = PRUDP_THRESH_INIT
	rpudp.dead_link = PRUDP_DEADLINK
	rpudp.output = output
	return rpudp
}

// newSegment creates a PRUDP segment
func (rpudp *PRUDP) newSegment(size int) (seg segment) {
	seg.data = transmitBuff.Get().([]byte)[:size]
	return
}

// if n >= mss
func (prudp *PRUDP) IsReserveMss(n int) bool {
	if n >= int(prudp.MTU-PRUDP_OVERHEAD) || n < 0 {
		return false
	}
	prudp.reserved = n
	prudp.mss = prudp.MTU - PRUDP_OVERHEAD - uint32(n)
	return true
}

// flush pending data
// TODO Optimization algorithm
func (prudp *PRUDP) flush(ackOnly bool) uint32 {
	var seg segment
	seg.session = prudp.session
	seg.cmd = PRUDP_CMD_ACK
	seg.wnd = prudp.wind_unused()
	seg.una = prudp.recv_next

	buffer := prudp.buffer
	// keep n bytes untouched
	ptr := buffer[prudp.reserved:]

	// makeSpace makes room for writing
	makeSpace := func(space int) {
		size := len(buffer) - len(ptr)
		if size+space > int(prudp.MTU) {
			prudp.output(buffer, size)
			ptr = buffer[prudp.reserved:]
		}
	}

	// flush bytes in buffer if there is any
	flushBuffer := func() {
		size := len(buffer) - len(ptr)
		if size > prudp.reserved {
			prudp.output(buffer, size)
		}
	}

	// flush acknowledges
	for i, ack := range prudp.acklist {
		makeSpace(PRUDP_OVERHEAD)
		// filter jitters caused by bufferbloat
		if _itimediff(ack.sn, prudp.recv_next) >= 0 || len(prudp.acklist)-1 == i {
			seg.sn, seg.ts = ack.sn, ack.ts
			ptr = seg.encode(ptr)
		}
	}
	prudp.acklist = prudp.acklist[0:0]

	if ackOnly { // flash remain ack segments
		flushBuffer()
		return prudp.interval
	}

	// probe window size (if remote window size equals zero)
	if prudp.remote_wind == 0 {
		current := currentMs()
		if prudp.probe_wait == 0 {
			prudp.probe_wait = PRUDP_PROBE_INIT
			prudp.ts_probe = current + prudp.probe_wait
		} else {
			if _itimediff(current, prudp.ts_probe) >= 0 {
				if prudp.probe_wait < PRUDP_PROBE_INIT {
					prudp.probe_wait = PRUDP_PROBE_INIT
				}
				prudp.probe_wait += prudp.probe_wait / 2
				if prudp.probe_wait > PRUDP_PROBE_LIMIT {
					prudp.probe_wait = PRUDP_PROBE_LIMIT
				}
				prudp.ts_probe = current + prudp.probe_wait
				prudp.probe |= PRUDP_ASK_SEND
			}
		}
	} else {
		prudp.ts_probe = 0
		prudp.probe_wait = 0
	}

	// flush window probing commands
	if (prudp.probe & PRUDP_ASK_SEND) != 0 {
		seg.cmd = PRUDP_CMD_WASK
		makeSpace(PRUDP_OVERHEAD)
		ptr = seg.encode(ptr)
	}

	// flush window probing commands
	if (prudp.probe & PRUDP_ASK_TELL) != 0 {
		seg.cmd = PRUDP_CMD_WINS
		makeSpace(PRUDP_OVERHEAD)
		ptr = seg.encode(ptr)
	}

	prudp.probe = 0

	// calculate window size
	cwnd := _imin_(prudp.send_wind, prudp.remote_wind)
	if prudp.flowCONwind == 0 {
		cwnd = _imin_(prudp.c_wind, cwnd)
	}

	// sliding window, controlled by snd_nxt && sna_una+cwnd
	newSegsCount := 0
	for k := range prudp.send_queue {
		if _itimediff(prudp.send_next, prudp.send_una+cwnd) >= 0 {
			break
		}
		newseg := prudp.send_queue[k]
		newseg.session = prudp.session
		newseg.cmd = PRUDP_CMD_PUSH
		newseg.sn = prudp.send_next
		prudp.send_buf = append(prudp.send_buf, newseg)
		prudp.send_next++
		newSegsCount++
	}
	if newSegsCount > 0 {
		prudp.send_queue = prudp.remove_front(prudp.send_queue, newSegsCount)
	}

	// calculate resent
	resent := uint32(prudp.fastReSend)
	if prudp.fastReSend <= 0 {
		resent = 0xffffffff
	}

	// check for retransmissions
	current := currentMs()
	var change, lostSegs, fastRetransSegs, earlyRetransSegs uint64
	minrto := int32(prudp.interval)

	ref := prudp.send_buf[:len(prudp.send_buf)] // for bounds check elimination
	for k := range ref {
		segment := &ref[k]
		needsend := false
		if segment.acked == 1 {
			continue
		}
		if segment.xmit == 0 { // initial transmit
			needsend = true
			segment.rto = prudp.net_rto
			segment.resendts = current + segment.rto
		} else if segment.fastack >= resent { // fast retransmit
			needsend = true
			segment.fastack = 0
			segment.rto = prudp.net_rto
			segment.resendts = current + segment.rto
			change++
			fastRetransSegs++
		} else if segment.fastack > 0 && newSegsCount == 0 { // early retransmit
			needsend = true
			segment.fastack = 0
			segment.rto = prudp.net_rto
			segment.resendts = current + segment.rto
			change++
			earlyRetransSegs++
		} else if _itimediff(current, segment.resendts) >= 0 { // RTO
			needsend = true
			if prudp.nodelay == 0 {
				segment.rto += prudp.net_rto
			} else {
				segment.rto += prudp.net_rto / 2
			}
			segment.fastack = 0
			segment.resendts = current + segment.rto
			lostSegs++
		}

		if needsend {
			current = currentMs()
			segment.xmit++
			segment.ts = current
			segment.wnd = seg.wnd
			segment.una = seg.una

			need := PRUDP_OVERHEAD + len(segment.data)
			makeSpace(need)
			ptr = segment.encode(ptr)
			copy(ptr, segment.data)
			ptr = ptr[len(segment.data):]

			if segment.xmit >= prudp.dead_link {
				prudp.state = 0xFFFFFFFF
			}
		}

		// get the nearest rto
		if rto := _itimediff(segment.resendts, current); rto > 0 && rto < minrto {
			minrto = rto
		}
	}

	// flash remain segments
	flushBuffer()

	// counter updates
	sum := lostSegs
	if lostSegs > 0 {
		atomic.AddUint64(&DefaultSnmp.LostSegs, lostSegs)
	}
	if fastRetransSegs > 0 {
		atomic.AddUint64(&DefaultSnmp.FastRetransSegs, fastRetransSegs)
		sum += fastRetransSegs
	}
	if earlyRetransSegs > 0 {
		atomic.AddUint64(&DefaultSnmp.EarlyRetransSegs, earlyRetransSegs)
		sum += earlyRetransSegs
	}
	if sum > 0 {
		atomic.AddUint64(&DefaultSnmp.RetransSegs, sum)
	}

	// cwnd update
	if prudp.flowCONwind == 0 {
		// update ssthresh
		// rate halving, https://tools.ietf.org/html/rfc6937
		if change > 0 {
			inflight := prudp.send_next - prudp.send_una
			prudp.ssthresh = inflight / 2
			if prudp.ssthresh < PRUDP_THRESH_MIN {
				prudp.ssthresh = PRUDP_THRESH_MIN
			}
			prudp.c_wind = prudp.ssthresh + resent
			prudp.incr = prudp.c_wind * prudp.mss
		}

		// congestion control, https://tools.ietf.org/html/rfc5681
		if lostSegs > 0 {
			prudp.ssthresh = cwnd / 2
			if prudp.ssthresh < PRUDP_THRESH_MIN {
				prudp.ssthresh = PRUDP_THRESH_MIN
			}
			prudp.c_wind = 1
			prudp.incr = prudp.mss
		}

		if prudp.c_wind < 1 {
			prudp.c_wind = 1
			prudp.incr = prudp.mss
		}
	}

	return uint32(minrto)
}

// window unused
func (prudp *PRUDP) wind_unused() uint16 {
	if len(prudp.recv_queue) < int(prudp.revc_wind) {
		return uint16(int(prudp.revc_wind) - len(prudp.recv_queue))
	}
	return 0
}

// remove front n elements from queue
// if the number of elements to remove is more than half of the size.
// just shift the rear elements to front, otherwise just reslice q to q[n:]
// then the cost of runtime.growslice can always be less than n/2
func (prudp *PRUDP) remove_front(q []segment, n int) []segment {
	if n > cap(q)/2 {
		newn := copy(q, q[n:])
		return q[:newn]
	}
	return q[n:]
}
