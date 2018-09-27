// Package kcp - A Fast and Reliable ARQ Protocol
package kcp

import (
	"encoding/binary"
	"sync/atomic"
)

const (
	IKCP_RTO_NDL     = 30  // no delay min rto
	IKCP_RTO_MIN     = 100 // normal min rto
	IKCP_RTO_DEF     = 200
	IKCP_RTO_MAX     = 60000
	IKCP_CMD_PUSH    = 81 // cmd: push data
	IKCP_CMD_ACK     = 82 // cmd: ack
	IKCP_CMD_WASK    = 83 // cmd: window probe (ask)
	IKCP_CMD_WINS    = 84 // cmd: window size (tell)
	IKCP_ASK_SEND    = 1  // need to send IKCP_CMD_WASK
	IKCP_ASK_TELL    = 2  // need to send IKCP_CMD_WINS
	IKCP_WND_SND     = 32
	IKCP_WND_RCV     = 32
	IKCP_MTU_DEF     = 1400
	IKCP_ACK_FAST    = 3
	IKCP_INTERVAL    = 100
	IKCP_OVERHEAD    = 24
	IKCP_DEADLINK    = 20
	IKCP_THRESH_INIT = 2
	IKCP_THRESH_MIN  = 2
	IKCP_PROBE_INIT  = 7000   // 7 secs to probe window size
	IKCP_PROBE_LIMIT = 120000 // up to 120 secs to probe window
)

// output_callback is a prototype which ought capture conn and call conn.Write
type output_callback func(buf []byte, size int)

/* encode 8 bits unsigned int */
func ikcp_encode8u(p []byte, c byte) []byte {
	p[0] = c
	return p[1:]
}

/* decode 8 bits unsigned int */
func ikcp_decode8u(p []byte, c *byte) []byte {
	*c = p[0]
	return p[1:]
}

/* encode 16 bits unsigned int (lsb) */
func ikcp_encode16u(p []byte, w uint16) []byte {
	binary.LittleEndian.PutUint16(p, w)
	return p[2:]
}

/* decode 16 bits unsigned int (lsb) */
func ikcp_decode16u(p []byte, w *uint16) []byte {
	*w = binary.LittleEndian.Uint16(p)
	return p[2:]
}

/* encode 32 bits unsigned int (lsb) */
func ikcp_encode32u(p []byte, l uint32) []byte {
	binary.LittleEndian.PutUint32(p, l)
	return p[4:]
}

/* decode 32 bits unsigned int (lsb) */
func ikcp_decode32u(p []byte, l *uint32) []byte {
	*l = binary.LittleEndian.Uint32(p)
	return p[4:]
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

/*
segment defines a KCP segment

下面是segment的类型及说明
1. 数据包
最基础的Segment，用于发送应用层数据给远端。 每个数据包会有自己的sn， 发送出去后不会立即从缓存池中删除，而是会等收到远端返回回来的ack包时才会从缓存中移除（两端通过sn确认哪些包已收到）

2 ACK包
告诉远端自己已收到了远端发送的某个数据包。

3 窗口大小探测包
询问远端的接收窗口大小。 本地发送数据时，会根据远端的窗口大小来控制发送的数据量。
每个数据包的包头中都会带有远端当前的接收窗口大小。 但是当远端的接收窗口大小为0时，本机将不会再向远端发送数据，此时也就不会有远端的回传数据从而导致无法更新远端窗口大小。
因此需要单独的一类远端窗口大小探测包，在远端接收窗口大小为0时，隔一段时间询问一次，从而让本地有机会再开始重新传数据。

4 窗口大小回应包
回应远端自己的数据接收窗口大小。
*/
type segment struct {
	// 发送端与接收端通信时的匹配数字，发送端发送的数据包中此值与接收端的conv值匹配一致时，接收端才会接受此包。
	// conv为一个表示会话编号的整数，和tcp的conv一样，通信双方需保证conv相同，相互的数据包才能够被认可
	conv uint32
	// cmd是command的缩写,指明Segment类型。 Segment类型有以下几种：
	// 1. IKCP_CMD_PUSH : 发送数据包给远端
	// 2. IKCP_CMD_ACK : ACK包，告诉远端自己收到了哪个数据包
	// 3. IKCP_CMD_WASK : 询问远端的数据接收窗口还剩余多少
	// 4. IKCP_CMD_WINS : 回应远端自己的数据接收窗口大小
	cmd uint8
	// frg是fragment的缩写，是一个Segment在一次Send的data中的倒序序号。
	// 在让KCP发送数据时，KCP会加入snd_queue的Segment分配序号，标记Segment是这次发送数据中的倒数第几个Segment。
	// 数据在发送出去时，由于mss的限制，数据可能被分成若干个Segment发送出去。在分segment的过程中，相应的序号就会被记录到frg中。
	// 接收端在接收到这些segment时，就会根据frg将若干个segment合并成一个，再返回给应用层。
	frg uint8
	// wnd是window的缩写； 滑动窗口大小，用于流控（Flow Control）
	// * 当Segment做为发送数据时，此wnd为本机滑动窗口大小，用于告诉远端自己窗口剩余多少
	// * 当Segment做为接收到数据时，此wnd为远端滑动窗口大小，本机知道了远端窗口剩余多少后，可以控制自己接下来发送数据的大小
	wnd uint16
	// timestamp, 当前Segment发送时的时间戳
	ts uint32
	// Sequence Number, Segment的编号
	sn uint32
	// unacknowledged, 表示此编号前的所有包都已收到了。
	una uint32
	// Retransmission TimeOut，即超时重传时间，在发送出去时根据之前的网络情况进行设置
	rto uint32
	// 基本类似于Segment发送的次数，每发送一次会自加一。用于统计该Segment被重传了几次，用于参考，进行调节
	xmit uint32
	// resend timestamp , 指定重发的时间戳，当当前时间超过这个时间时，则再重发一次这个包
	resendts uint32
	// 用于以数据驱动的快速重传机制
	fastack uint32
	// 数据
	data []byte
}

// encode a segment into buffer
func (seg *segment) encode(ptr []byte) []byte {
	ptr = ikcp_encode32u(ptr, seg.conv)
	ptr = ikcp_encode8u(ptr, seg.cmd)
	ptr = ikcp_encode8u(ptr, seg.frg)
	ptr = ikcp_encode16u(ptr, seg.wnd)
	ptr = ikcp_encode32u(ptr, seg.ts)
	ptr = ikcp_encode32u(ptr, seg.sn)
	ptr = ikcp_encode32u(ptr, seg.una)
	ptr = ikcp_encode32u(ptr, uint32(len(seg.data)))
	atomic.AddUint64(&DefaultSnmp.OutSegs, 1)
	return ptr
}

// KCP defines a single KCP connection
type KCP struct {
	conv, mtu, mss, state uint32 // conv：回话id
	// 当前未收到确认回传的发送出去的包的最小编号。也就是此编号前的包都已经收到确认回传了
	snd_una uint32
	snd_nxt uint32 // 下一个要发送出去的包编号
	// 下一个要接收的数据包的编号。也就是说此序号之前的包都已经按顺序全部收到了，下面期望收到这个序号的包（已保证数据包的连续性、顺序性
	rcv_nxt              uint32
	ssthresh             uint32
	rx_rttvar, rx_srtt   int32
	rx_rto, rx_minrto    uint32 // tx_rto：由ack接收延迟计算出来的超时重传时间
	snd_wnd              uint32 // 发送窗口大小
	rmt_wnd              uint32 // 远端的接收窗口大小, rmt是remote
	rcv_wnd              uint32 // 接收窗口大小
	cwnd, probe          uint32
	interval, ts_flush   uint32
	nodelay, updated     uint32 // nodelay：0-表示不启动快速重传模式
	ts_probe, probe_wait uint32
	dead_link, incr      uint32

	fastresend     int32
	nocwnd, stream int32
	// 发送队列。应用层的数据（在调用KCP.Send后）会进入此队列中，KCP在flush的时候根据发送窗口的大小，再决定将多少个Segment放入到snd_buf中进行发送
	snd_queue []segment
	// 缓存 接收到的连续的数据包
	rcv_queue []segment
	// 发送缓存池。发送出去的数据将会呆在这个池子中，等待远端的回传确认，等收到远端确认此包收到后再从snd_buf移出去。
	// KCP在每次flush的时候都会检查这个缓存池中的每个Segment，如果超时或者判定丢包就会重发。
	snd_buf []segment
	// 接收到的数据会先存放到rcv_buf中。 因为数据可能是乱序到达本地的，所以接受到的数据会按sn顺序依次放入到对应的位置中。
	// 当sn从低到高连续的数据包都收到了，则将这批连续的数据包转移到rcv_queue中。这样就保证了数据包的顺序性。
	rcv_buf []segment

	// 收到包后要发送的回传确认。 在收到包时先将要回传ack的sn放入此队列中，在flush函数中再发出去。
	// acklist中，一个ack以(sn,timestampe)为一组的方式存储。即 [{sn1,ts1},{sn2,ts2} … ] 即 [sn1,ts1,sn2,ts2 … ]
	acklist []ackItem

	buffer []byte
	output output_callback
}

type ackItem struct {
	sn uint32
	ts uint32
}

// NewKCP create a new kcp control object, 'conv' must equal in two endpoint
// from the same connection.
func NewKCP(conv uint32, output output_callback) *KCP {
	kcp := new(KCP)
	kcp.conv = conv
	kcp.snd_wnd = IKCP_WND_SND
	kcp.rcv_wnd = IKCP_WND_RCV
	kcp.rmt_wnd = IKCP_WND_RCV
	kcp.mtu = IKCP_MTU_DEF
	kcp.mss = kcp.mtu - IKCP_OVERHEAD
	kcp.buffer = make([]byte, (kcp.mtu+IKCP_OVERHEAD)*3)
	kcp.rx_rto = IKCP_RTO_DEF
	kcp.rx_minrto = IKCP_RTO_MIN
	kcp.interval = IKCP_INTERVAL
	kcp.ts_flush = IKCP_INTERVAL
	kcp.ssthresh = IKCP_THRESH_INIT
	kcp.dead_link = IKCP_DEADLINK
	kcp.output = output
	return kcp
}

// newSegment creates a KCP segment
func (kcp *KCP) newSegment(size int) (seg segment) {
	seg.data = xmitBuf.Get().([]byte)[:size]
	return
}

// delSegment recycles a KCP segment
func (kcp *KCP) delSegment(seg segment) {
	xmitBuf.Put(seg.data)
}

// PeekSize checks the size of next message in the recv queue
func (kcp *KCP) PeekSize() (length int) {
	if len(kcp.rcv_queue) == 0 {
		return -1
	}

	seg := &kcp.rcv_queue[0]
	if seg.frg == 0 {
		return len(seg.data)
	}

	if len(kcp.rcv_queue) < int(seg.frg+1) {
		return -1
	}

	for k := range kcp.rcv_queue {
		seg := &kcp.rcv_queue[k]
		length += len(seg.data)
		if seg.frg == 0 {
			break
		}
	}
	return
}

// Recv is user/upper level recv: returns size, returns below zero for EAGAIN
func (kcp *KCP) Recv(buffer []byte) (n int) {
	if len(kcp.rcv_queue) == 0 {
		return -1
	}

	peeksize := kcp.PeekSize()
	if peeksize < 0 {
		return -2
	}

	if peeksize > len(buffer) {
		return -3
	}

	var fast_recover bool
	if len(kcp.rcv_queue) >= int(kcp.rcv_wnd) {
		fast_recover = true
	}

	// merge fragment
	count := 0
	for k := range kcp.rcv_queue {
		seg := &kcp.rcv_queue[k]
		copy(buffer, seg.data)
		buffer = buffer[len(seg.data):]
		n += len(seg.data)
		count++
		kcp.delSegment(*seg)
		if seg.frg == 0 {
			break
		}
	}
	if count > 0 {
		kcp.rcv_queue = kcp.remove_front(kcp.rcv_queue, count)
	}

	// move available data from rcv_buf -> rcv_queue
	count = 0
	for k := range kcp.rcv_buf {
		seg := &kcp.rcv_buf[k]
		if seg.sn == kcp.rcv_nxt && len(kcp.rcv_queue) < int(kcp.rcv_wnd) {
			kcp.rcv_nxt++
			count++
		} else {
			break
		}
	}

	if count > 0 {
		kcp.rcv_queue = append(kcp.rcv_queue, kcp.rcv_buf[:count]...)
		kcp.rcv_buf = kcp.remove_front(kcp.rcv_buf, count)
	}

	// fast recover
	if len(kcp.rcv_queue) < int(kcp.rcv_wnd) && fast_recover {
		// ready to send back IKCP_CMD_WINS in ikcp_flush
		// tell remote my window size
		kcp.probe |= IKCP_ASK_TELL
	}
	return
}

// Send is user/upper level send, returns below zero for error
func (kcp *KCP) Send(buffer []byte) int {
	var count int
	if len(buffer) == 0 {
		return -1
	}

	// append to previous segment in streaming mode (if possible)
	if kcp.stream != 0 {
		n := len(kcp.snd_queue)
		if n > 0 {
			seg := &kcp.snd_queue[n-1]
			if len(seg.data) < int(kcp.mss) {
				capacity := int(kcp.mss) - len(seg.data)
				extend := capacity
				if len(buffer) < capacity {
					extend = len(buffer)
				}

				// grow slice, the underlying cap is guaranteed to
				// be larger than kcp.mss
				oldlen := len(seg.data)
				seg.data = seg.data[:oldlen+extend]
				copy(seg.data[oldlen:], buffer)
				buffer = buffer[extend:]
			}
		}

		if len(buffer) == 0 {
			return 0
		}
	}

	if len(buffer) <= int(kcp.mss) {
		count = 1
	} else {
		count = (len(buffer) + int(kcp.mss) - 1) / int(kcp.mss)
	}

	if count > 255 {
		return -2
	}

	if count == 0 {
		count = 1
	}

	for i := 0; i < count; i++ {
		var size int
		if len(buffer) > int(kcp.mss) {
			size = int(kcp.mss)
		} else {
			size = len(buffer)
		}
		seg := kcp.newSegment(size)
		copy(seg.data, buffer[:size])
		if kcp.stream == 0 { // message mode
			seg.frg = uint8(count - i - 1)
		} else { // stream mode
			seg.frg = 0
		}
		kcp.snd_queue = append(kcp.snd_queue, seg)
		buffer = buffer[size:]
	}
	return 0
}

func (kcp *KCP) update_ack(rtt int32) {
	// https://tools.ietf.org/html/rfc6298
	var rto uint32
	if kcp.rx_srtt == 0 {
		kcp.rx_srtt = rtt
		kcp.rx_rttvar = rtt >> 1
	} else {
		delta := rtt - kcp.rx_srtt
		kcp.rx_srtt += delta >> 3
		if delta < 0 {
			delta = -delta
		}
		if rtt < kcp.rx_srtt-kcp.rx_rttvar {
			// if the new RTT sample is below the bottom of the range of
			// what an RTT measurement is expected to be.
			// give an 8x reduced weight versus its normal weighting
			kcp.rx_rttvar += (delta - kcp.rx_rttvar) >> 5
		} else {
			kcp.rx_rttvar += (delta - kcp.rx_rttvar) >> 2
		}
	}
	rto = uint32(kcp.rx_srtt) + _imax_(kcp.interval, uint32(kcp.rx_rttvar)<<2)
	kcp.rx_rto = _ibound_(kcp.rx_minrto, rto, IKCP_RTO_MAX)
}

func (kcp *KCP) shrink_buf() {
	if len(kcp.snd_buf) > 0 {
		seg := &kcp.snd_buf[0]
		kcp.snd_una = seg.sn
	} else {
		kcp.snd_una = kcp.snd_nxt
	}
}

func (kcp *KCP) parse_ack(sn uint32) {
	if _itimediff(sn, kcp.snd_una) < 0 || _itimediff(sn, kcp.snd_nxt) >= 0 {
		return
	}

	for k := range kcp.snd_buf {
		seg := &kcp.snd_buf[k]
		if sn == seg.sn {
			kcp.delSegment(*seg)
			copy(kcp.snd_buf[k:], kcp.snd_buf[k+1:])
			kcp.snd_buf[len(kcp.snd_buf)-1] = segment{}
			kcp.snd_buf = kcp.snd_buf[:len(kcp.snd_buf)-1]
			break
		}
		if _itimediff(sn, seg.sn) < 0 {
			break
		}
	}
}

func (kcp *KCP) parse_fastack(sn uint32) {
	if _itimediff(sn, kcp.snd_una) < 0 || _itimediff(sn, kcp.snd_nxt) >= 0 {
		return
	}

	for k := range kcp.snd_buf {
		seg := &kcp.snd_buf[k]
		if _itimediff(sn, seg.sn) < 0 {
			break
		} else if sn != seg.sn {
			seg.fastack++
		}
	}
}

func (kcp *KCP) parse_una(una uint32) {
	count := 0
	for k := range kcp.snd_buf {
		seg := &kcp.snd_buf[k]
		if _itimediff(una, seg.sn) > 0 {
			kcp.delSegment(*seg)
			count++
		} else {
			break
		}
	}
	if count > 0 {
		kcp.snd_buf = kcp.remove_front(kcp.snd_buf, count)
	}
}

// ack append
func (kcp *KCP) ack_push(sn, ts uint32) {
	kcp.acklist = append(kcp.acklist, ackItem{sn, ts})
}

func (kcp *KCP) parse_data(newseg segment) {
	sn := newseg.sn
	if _itimediff(sn, kcp.rcv_nxt+kcp.rcv_wnd) >= 0 ||
		_itimediff(sn, kcp.rcv_nxt) < 0 {
		kcp.delSegment(newseg)
		return
	}

	n := len(kcp.rcv_buf) - 1
	insert_idx := 0
	repeat := false
	for i := n; i >= 0; i-- {
		seg := &kcp.rcv_buf[i]
		if seg.sn == sn {
			repeat = true
			atomic.AddUint64(&DefaultSnmp.RepeatSegs, 1)
			break
		}
		if _itimediff(sn, seg.sn) > 0 {
			insert_idx = i + 1
			break
		}
	}

	if !repeat {
		if insert_idx == n+1 {
			kcp.rcv_buf = append(kcp.rcv_buf, newseg)
		} else {
			kcp.rcv_buf = append(kcp.rcv_buf, segment{})
			copy(kcp.rcv_buf[insert_idx+1:], kcp.rcv_buf[insert_idx:])
			kcp.rcv_buf[insert_idx] = newseg
		}
	} else {
		kcp.delSegment(newseg)
	}

	// move available data from rcv_buf -> rcv_queue
	count := 0
	for k := range kcp.rcv_buf {
		seg := &kcp.rcv_buf[k]
		if seg.sn == kcp.rcv_nxt && len(kcp.rcv_queue) < int(kcp.rcv_wnd) {
			kcp.rcv_nxt++
			count++
		} else {
			break
		}
	}
	if count > 0 {
		kcp.rcv_queue = append(kcp.rcv_queue, kcp.rcv_buf[:count]...)
		kcp.rcv_buf = kcp.remove_front(kcp.rcv_buf, count)
	}
}

// Input when you received a low level packet (eg. UDP packet), call it
// regular indicates a regular packet has received(not from FEC)
func (kcp *KCP) Input(data []byte, regular, ackNoDelay bool) int {
	snd_una := kcp.snd_una
	if len(data) < IKCP_OVERHEAD {
		return -1
	}

	var maxack uint32
	var lastackts uint32
	var flag int
	var inSegs uint64

	for {
		var ts, sn, length, una, conv uint32
		var wnd uint16
		var cmd, frg uint8

		if len(data) < int(IKCP_OVERHEAD) {
			break
		}

		data = ikcp_decode32u(data, &conv)
		if conv != kcp.conv {
			return -1
		}

		// 解析出数据中的KCP头部
		data = ikcp_decode8u(data, &cmd)
		data = ikcp_decode8u(data, &frg)
		data = ikcp_decode16u(data, &wnd)
		data = ikcp_decode32u(data, &ts)
		data = ikcp_decode32u(data, &sn)
		data = ikcp_decode32u(data, &una)
		data = ikcp_decode32u(data, &length)
		if len(data) < int(length) {
			return -2
		}

		if cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
			cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS {
			return -3
		}

		// only trust window updates from regular packets. i.e: latest update
		if regular {
			// 获得远端的窗口大小
			kcp.rmt_wnd = uint32(wnd)
		}
		// 分析una，看哪些segment远端收到了，把远端收到的segment从snd_buf中移除
		kcp.parse_una(una)
		kcp.shrink_buf()

		if cmd == IKCP_CMD_ACK {
			// 如果收到的是远端发来的ACK包

			// 分析具体是哪个segment被收到了，将其从snd_buf中移除
			// 同时给snd_buf中的其它segment的fastack字段增加计数++
			kcp.parse_ack(sn)
			// 因为snd_buf可能改变了，更新当前的snd_una
			kcp.shrink_buf()
			// 因为此时收到远端的ack，所以我们知道远端的包到本机的时间，因此可统计当前的网速如何，进行调整。这里是可以更新rto的，但是没有看到代码
			if flag == 0 {
				flag = 1
				maxack = sn
				lastackts = ts
			} else if _itimediff(sn, maxack) > 0 {
				maxack = sn
				lastackts = ts
			}
		} else if cmd == IKCP_CMD_PUSH {
			// 如果收到的是远端发来的数据包

			// 如果还有足够多的接收窗口
			if _itimediff(sn, kcp.rcv_nxt+kcp.rcv_wnd) < 0 {
				// push当前包的ack给远端（会在flush中发送ack出去)
				kcp.ack_push(sn, ts)
				if _itimediff(sn, kcp.rcv_nxt) >= 0 {
					// 如果当前segment还没被接收过sn >= rcv_next
					seg := kcp.newSegment(int(length))
					seg.conv = conv
					seg.cmd = cmd
					seg.frg = frg
					seg.wnd = wnd
					seg.ts = ts
					seg.sn = sn
					seg.una = una
					copy(seg.data, data[:length])
					// 根据segment.sn分析当前segment与rcv_buf中的那些segment的关系
					// 1. 如果已经接收过了，则丢弃
					// 2. 否则将其按sn的顺序插入到rcv_buf中对应的位置中去
					// 3. 按顺序将sn连续在一起的segment转移转移到rcv_queue中
					kcp.parse_data(seg)
				} else {
					// 重复的包，丢弃
					atomic.AddUint64(&DefaultSnmp.RepeatSegs, 1)
				}
			} else {
				atomic.AddUint64(&DefaultSnmp.RepeatSegs, 1)
			}
		} else if cmd == IKCP_CMD_WASK {
			// 如果收到的包是远端发过来询问窗口大小的包

			// ready to send back IKCP_CMD_WINS in Ikcp_flush
			// tell remote my window size
			kcp.probe |= IKCP_ASK_TELL
		} else if cmd == IKCP_CMD_WINS {
			// do nothing
		} else {
			return -3 // 不接受其他命令
		}

		inSegs++
		data = data[length:]
	}
	atomic.AddUint64(&DefaultSnmp.InSegs, inSegs)

	// 根据收到包头的信息，更新网络情况的统计数据，方便进行流控

	if flag != 0 && regular {
		kcp.parse_fastack(maxack)
		current := currentMs()
		if _itimediff(current, lastackts) >= 0 {
			kcp.update_ack(_itimediff(current, lastackts))
		}
	}

	if _itimediff(kcp.snd_una, snd_una) > 0 {
		if kcp.cwnd < kcp.rmt_wnd {
			mss := kcp.mss
			if kcp.cwnd < kcp.ssthresh {
				kcp.cwnd++
				kcp.incr += mss
			} else {
				if kcp.incr < mss {
					kcp.incr = mss
				}
				kcp.incr += (mss*mss)/kcp.incr + (mss / 16)
				if (kcp.cwnd+1)*mss <= kcp.incr {
					kcp.cwnd++
				}
			}
			if kcp.cwnd > kcp.rmt_wnd {
				kcp.cwnd = kcp.rmt_wnd
				kcp.incr = kcp.rmt_wnd * mss
			}
		}
	}

	if ackNoDelay && len(kcp.acklist) > 0 { // ack immediately
		kcp.flush(true)
	}
	return 0
}

func (kcp *KCP) wnd_unused() uint16 {
	if len(kcp.rcv_queue) < int(kcp.rcv_wnd) {
		return uint16(int(kcp.rcv_wnd) - len(kcp.rcv_queue))
	}
	return 0
}

// flush pending data
func (kcp *KCP) flush(ackOnly bool) {
	var seg segment
	seg.conv = kcp.conv
	seg.cmd = IKCP_CMD_ACK
	seg.wnd = kcp.wnd_unused()
	seg.una = kcp.rcv_nxt

	buffer := kcp.buffer
	// flush acknowledges
	// 将前面收到数据时，压进ack发送队列的ack发送出去
	ptr := buffer
	for i, ack := range kcp.acklist {
		size := len(buffer) - len(ptr)
		if size+IKCP_OVERHEAD > int(kcp.mtu) {
			kcp.output(buffer, size)
			ptr = buffer
		}
		// filter jitters caused by bufferbloat
		if ack.sn >= kcp.rcv_nxt || len(kcp.acklist)-1 == i {
			seg.sn, seg.ts = ack.sn, ack.ts
			ptr = seg.encode(ptr)
		}
	}
	kcp.acklist = kcp.acklist[0:0]

	if ackOnly { // flash remain ack segments
		size := len(buffer) - len(ptr)
		if size > 0 {
			kcp.output(buffer, size)
		}
		return
	}

	// probe window size (if remote window size equals zero)
	// 在远端窗口大小为0时，探测远端窗口大小。为远端窗口大小为0时，远端已没有窗口可接收数据，此时不该再发，会造成远端处理不过来
	if kcp.rmt_wnd == 0 {
		current := currentMs()
		if kcp.probe_wait == 0 {
			kcp.probe_wait = IKCP_PROBE_INIT
			kcp.ts_probe = current + kcp.probe_wait
		} else {
			if _itimediff(current, kcp.ts_probe) >= 0 {
				if kcp.probe_wait < IKCP_PROBE_INIT {
					kcp.probe_wait = IKCP_PROBE_INIT
				}
				kcp.probe_wait += kcp.probe_wait / 2
				if kcp.probe_wait > IKCP_PROBE_LIMIT {
					kcp.probe_wait = IKCP_PROBE_LIMIT
				}
				kcp.ts_probe = current + kcp.probe_wait
				kcp.probe |= IKCP_ASK_SEND
			}
		}
	} else {
		kcp.ts_probe = 0
		kcp.probe_wait = 0
	}

	// flush window probing commands
	if (kcp.probe & IKCP_ASK_SEND) != 0 {
		seg.cmd = IKCP_CMD_WASK
		size := len(buffer) - len(ptr)
		if size+IKCP_OVERHEAD > int(kcp.mtu) {
			kcp.output(buffer, size)
			ptr = buffer
		}
		ptr = seg.encode(ptr)
	}

	// flush window probing commands
	if (kcp.probe & IKCP_ASK_TELL) != 0 {
		seg.cmd = IKCP_CMD_WINS
		size := len(buffer) - len(ptr)
		if size+IKCP_OVERHEAD > int(kcp.mtu) {
			kcp.output(buffer, size)
			ptr = buffer
		}
		ptr = seg.encode(ptr)
	}

	kcp.probe = 0

	// calculate window size
	cwnd := _imin_(kcp.snd_wnd, kcp.rmt_wnd)
	if kcp.nocwnd == 0 {
		cwnd = _imin_(kcp.cwnd, cwnd)
	}

	// sliding window, controlled by snd_nxt && sna_una+cwnd
	// 转移snd_queue中的数据到snd_buf中，以便后面发送出去
	newSegsCount := 0
	for k := range kcp.snd_queue {
		if _itimediff(kcp.snd_nxt, kcp.snd_una+cwnd) >= 0 { // 已经没有发送窗口了，不发送新数据
			break
		}
		newseg := kcp.snd_queue[k]
		newseg.conv = kcp.conv
		newseg.cmd = IKCP_CMD_PUSH
		newseg.sn = kcp.snd_nxt
		kcp.snd_buf = append(kcp.snd_buf, newseg)
		kcp.snd_nxt++
		newSegsCount++
		kcp.snd_queue[k].data = nil
	}
	if newSegsCount > 0 {
		kcp.snd_queue = kcp.remove_front(kcp.snd_queue, newSegsCount)
	}

	// calculate resent
	// 计算重传时间
	resent := uint32(kcp.fastresend)
	if kcp.fastresend <= 0 {
		resent = 0xffffffff
	}

	// check for retransmissions
	current := currentMs()
	var change, lost, lostSegs, fastRetransSegs, earlyRetransSegs uint64
	// 根据各个segment的发送情况发送segment
	for k := range kcp.snd_buf {
		segment := &kcp.snd_buf[k]
		needsend := false
		if segment.xmit == 0 { // initial transmit
			// 该segment是第一次发送，需要发送出去
			needsend = true
			segment.rto = kcp.rx_rto
			segment.resendts = current + segment.rto
		} else if _itimediff(current, segment.resendts) >= 0 { // RTO
			// 当前时间已经到了该segment的重发时间（却还在snd_buf中，证明一直没收到该segment的ack，可认为这个segment丢了），也需要发送出去
			needsend = true
			if kcp.nodelay == 0 {
				segment.rto += kcp.rx_rto
			} else {
				segment.rto += kcp.rx_rto / 2
			}
			segment.resendts = current + segment.rto
			lost++
			lostSegs++
		} else if segment.fastack >= resent { // fast retransmit
			// 该segment的fastack大于resent了，也认为需要重发出去
			// 1. fastack是个计数器，每次收到远端的ack包时，而该包又不属于自己的ack包时，该值就会加
			// 2. resent由fastresend赋值，fastresend可由外部配置是否快速重传
			// 3. 这个条件可加快丢包重传，但会浪费多点带宽（因为可能该segment只是到达的慢一点而已，这个会导致有更高的概率重传多次同一个segment）
			needsend = true
			segment.fastack = 0
			segment.rto = kcp.rx_rto
			segment.resendts = current + segment.rto
			change++
			fastRetransSegs++
		} else if segment.fastack > 0 && newSegsCount == 0 { // early retransmit
			needsend = true
			segment.fastack = 0
			segment.rto = kcp.rx_rto
			segment.resendts = current + segment.rto
			change++
			earlyRetransSegs++
		}

		if needsend {
			segment.xmit++
			segment.ts = current
			segment.wnd = seg.wnd
			segment.una = seg.una

			size := len(buffer) - len(ptr)
			need := IKCP_OVERHEAD + len(segment.data)

			if size+need > int(kcp.mtu) {
				kcp.output(buffer, size)
				current = currentMs() // time update for a blocking call
				ptr = buffer
			}

			ptr = segment.encode(ptr)
			copy(ptr, segment.data)
			ptr = ptr[len(segment.data):]

			if segment.xmit >= kcp.dead_link {
				kcp.state = 0xFFFFFFFF
			}
		}
	}

	// flash remain segments
	size := len(buffer) - len(ptr)
	if size > 0 {
		kcp.output(buffer, size)
	}

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

	// update ssthresh
	// rate halving, https://tools.ietf.org/html/rfc6937
	if change > 0 {
		inflight := kcp.snd_nxt - kcp.snd_una
		kcp.ssthresh = inflight / 2
		if kcp.ssthresh < IKCP_THRESH_MIN {
			kcp.ssthresh = IKCP_THRESH_MIN
		}
		kcp.cwnd = kcp.ssthresh + resent
		kcp.incr = kcp.cwnd * kcp.mss
	}

	// congestion control, https://tools.ietf.org/html/rfc5681
	if lost > 0 {
		kcp.ssthresh = cwnd / 2
		if kcp.ssthresh < IKCP_THRESH_MIN {
			kcp.ssthresh = IKCP_THRESH_MIN
		}
		kcp.cwnd = 1
		kcp.incr = kcp.mss
	}

	if kcp.cwnd < 1 {
		kcp.cwnd = 1
		kcp.incr = kcp.mss
	}
}

// Update updates state (call it repeatedly, every 10ms-100ms), or you can ask
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec.
func (kcp *KCP) Update() {
	var slap int32

	current := currentMs()
	if kcp.updated == 0 {
		kcp.updated = 1
		kcp.ts_flush = current
	}

	slap = _itimediff(current, kcp.ts_flush)

	if slap >= 10000 || slap < -10000 {
		kcp.ts_flush = current
		slap = 0
	}

	if slap >= 0 {
		kcp.ts_flush += kcp.interval
		if _itimediff(current, kcp.ts_flush) >= 0 {
			kcp.ts_flush = current + kcp.interval
		}
		kcp.flush(false)
	}
}

// Check determines when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to
// schedule ikcp_update (eg. implementing an epoll-like mechanism,
// or optimize ikcp_update when handling massive kcp connections)
func (kcp *KCP) Check() uint32 {
	current := currentMs()
	ts_flush := kcp.ts_flush
	tm_flush := int32(0x7fffffff)
	tm_packet := int32(0x7fffffff)
	minimal := uint32(0)
	if kcp.updated == 0 {
		return current
	}

	if _itimediff(current, ts_flush) >= 10000 ||
		_itimediff(current, ts_flush) < -10000 {
		ts_flush = current
	}

	if _itimediff(current, ts_flush) >= 0 {
		return current
	}

	tm_flush = _itimediff(ts_flush, current)

	for k := range kcp.snd_buf {
		seg := &kcp.snd_buf[k]
		diff := _itimediff(seg.resendts, current)
		if diff <= 0 {
			return current
		}
		if diff < tm_packet {
			tm_packet = diff
		}
	}

	minimal = uint32(tm_packet)
	if tm_packet >= tm_flush {
		minimal = uint32(tm_flush)
	}
	if minimal >= kcp.interval {
		minimal = kcp.interval
	}

	return current + minimal
}

// SetMtu changes MTU size, default is 1400
func (kcp *KCP) SetMtu(mtu int) int {
	if mtu < 50 || mtu < IKCP_OVERHEAD {
		return -1
	}
	buffer := make([]byte, (mtu+IKCP_OVERHEAD)*3)
	if buffer == nil {
		return -2
	}
	kcp.mtu = uint32(mtu)
	kcp.mss = kcp.mtu - IKCP_OVERHEAD
	kcp.buffer = buffer
	return 0
}

// NoDelay options
// fastest: ikcp_nodelay(kcp, 1, 20, 2, 1)
// nodelay: 0:disable(default), 1:enable
// interval: internal update timer interval in millisec, default is 100ms
// resend: 0:disable fast resend(default), 1:enable fast resend
// nc: 0:normal congestion control(default), 1:disable congestion control
func (kcp *KCP) NoDelay(nodelay, interval, resend, nc int) int {
	if nodelay >= 0 {
		kcp.nodelay = uint32(nodelay)
		if nodelay != 0 {
			kcp.rx_minrto = IKCP_RTO_NDL
		} else {
			kcp.rx_minrto = IKCP_RTO_MIN
		}
	}
	if interval >= 0 {
		if interval > 5000 {
			interval = 5000
		} else if interval < 10 {
			interval = 10
		}
		kcp.interval = uint32(interval)
	}
	if resend >= 0 {
		kcp.fastresend = int32(resend)
	}
	if nc >= 0 {
		kcp.nocwnd = int32(nc)
	}
	return 0
}

// WndSize sets maximum window size: sndwnd=32, rcvwnd=32 by default
func (kcp *KCP) WndSize(sndwnd, rcvwnd int) int {
	if sndwnd > 0 {
		kcp.snd_wnd = uint32(sndwnd)
	}
	if rcvwnd > 0 {
		kcp.rcv_wnd = uint32(rcvwnd)
	}
	return 0
}

// WaitSnd gets how many packet is waiting to be sent
func (kcp *KCP) WaitSnd() int {
	return len(kcp.snd_buf) + len(kcp.snd_queue)
}

// remove front n elements from queue
func (kcp *KCP) remove_front(q []segment, n int) []segment {
	newn := copy(q, q[n:])
	for i := newn; i < len(q); i++ {
		q[i] = segment{} // manual set nil for GC
	}
	return q[:newn]
}
