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
	// Sequence Number, Segment的编号，sn和frg是完全不一样的，sn是一个全局的东西，通过kcp.snd_nxt赋值，
	// 而frg是针对一个大的数据包切成多个segment的设定，用于将多个segment恢复成原始报文
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
/*
|<------------ 4 bytes ------------>|
+--------+--------+--------+--------+
|  conv                             | conv：Conversation, 会话序号，用于标识收发数据包是否一致
+--------+--------+--------+--------+ cmd: Command, 指令类型，代表这个Segment的类型
|  cmd   |  frg   |  wnd            | frg: Fragment, 分段序号，分段从大到小，0代表数据包接收完毕
+--------+--------+--------+--------+ wnd: Window, 窗口大小
|  ts                               | ts: Timestamp, 发送的时间戳
+--------+--------+--------+--------+
|  sn                               | sn: Sequence Number, Segment序号
+--------+--------+--------+--------+
|  una                              | una: Unacknowledged, 当前未收到的序号，
+--------+--------+--------+--------+      即代表这个序号之前的包均收到
|  len                              | len: Length, 后续数据的长度
+--------+--------+--------+--------+
*/
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
	// 回话id，需要两端保持一致，那么如何保持一致呢？
	// server端的conv是client端带过去的，在Listener.monitor中，会用client的conv_id来创建UDPSession
	conv            uint32
	mtu, mss, state uint32
	// 当前未收到确认回传的发送出去的包的最小编号。也就是此编号前的包都已经收到确认回传了
	snd_una uint32
	snd_nxt uint32 // 下一个要发送出去的包编号
	// 下一个要接收的数据包的编号。也就是说此序号之前的包都已经按顺序全部收到了，下面期望收到这个序号的包（已保证数据包的连续性、顺序性
	rcv_nxt            uint32
	ssthresh           uint32
	rx_rttvar, rx_srtt int32
	rx_rto, rx_minrto  uint32 // tx_rto：由ack接收延迟计算出来的超时重传时间
	snd_wnd            uint32 // 发送窗口大小（窗口的计量单位是segment，不是字节）
	rmt_wnd            uint32 // 远端的接收窗口大小, rmt是remote
	rcv_wnd            uint32 // 接收窗口大小
	cwnd, probe        uint32
	interval, ts_flush uint32
	nodelay, updated   uint32 // nodelay：0-表示不启动快速重传模式
	ts_probe           uint32 // 下次窗口探测的时间
	probe_wait         uint32
	dead_link, incr    uint32

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

	// 真正要发送出去的payload
	buffer []byte
	output output_callback // 回调，真正发送数据的地方，底层协议的抽象比如（UDP）
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

	// 下一个完整的包没有收全
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
	// 检查本次接收数据之后，是否需要进行窗口恢复。
	// KCP 协议在远端窗口为0的时候将会停止发送数据，此时如果远端调用 recv 将数据从 rcv_buffer 中移动到应用层 queue 中之后，
	// 表明其可以再次接受数据，为了能够恢复数据的发送，远端可以主动发送 IKCP_ASK_TELL 来告知窗口大小
	if len(kcp.rcv_queue) >= int(kcp.rcv_wnd) {
		fast_recover = true
	}

	// merge fragment
	count := 0
	// 开始将 rcv_queue 中的数据根据分片编号 frg merge 起来，然后拷贝到用户的 buffer 中。
	// 这里循环遍历 rcv_queue，按序拷贝数据，当碰到某个 segment 的 frg 为 0 时跳出循环，表明本次数据接收结束，
	// 这点应该很好理解，经过 send 发送的数据会进行分片，分片编号为倒序序号，因此 frg 为 0 的数据包标记着完整接收到了一次 send 发送过来的数据
	for k := range kcp.rcv_queue {
		seg := &kcp.rcv_queue[k]
		copy(buffer, seg.data)
		buffer = buffer[len(seg.data):] // buffer是传进来的，容量管够(PeekSize)，这里看上去buffer变了，但是外部有buffer原始的首地址
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
	// 将rcv_buf 中的数据转移到 rcv_queue 中，这个过程根据报文的 sn 编号来确保转移到 rcv_queue 中的数据一定是按序的，这里和parse_data中的最后一部分完全一样
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
	// 最后进行窗口恢复。此时如果 recover 标记为1，表明在此次接收之前，可用接收窗口为0，如果经过本次接收之后，可用窗口大于0，
	// 将主动发送 IKCP_ASK_TELL 数据包来通知对方已可以接收数据
	if len(kcp.rcv_queue) < int(kcp.rcv_wnd) && fast_recover {
		// ready to send back IKCP_CMD_WINS in ikcp_flush
		// tell remote my window size
		kcp.probe |= IKCP_ASK_TELL
	}
	return
}

// Send is user/upper level send, returns below zero for error
// Send确实是一个上层API(相对于flush等)，但是并不能称为一个user level的API，在kcp的使用中，用户能接触到的是
// UDPSession，而不会直接调用KCP的方法
func (kcp *KCP) Send(buffer []byte) int {
	var count int
	if len(buffer) == 0 {
		return -1
	}

	// append to previous segment in streaming mode (if possible)
	// 1. 如果当前的 KCP 开启流模式，取出 `snd_queue` 中的最后一个报文，将其填充到mss的长度，并设置其frg为0.
	// 对于被填充的那个包而言，仅仅是将一部分数据append到之前的数据后面，至于拆分，应该是应用层需要做的工作.
	// 另外注意，这里只是将数据包装成segment而已，还没有走到发送，在flush中会真正构造数据包，len也是这个时候计算的
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

	// 2. 计算剩下的数据要分成几段
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

	// 3. 为剩下的数据创建KCP Segment
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
			seg.frg = uint8(count - i - 1) // 发送顺序从大到小
		} else { // stream mode, 流模式下分片编号不用填写
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
			// 归还seg.data，seg.data是从sync.pool中获取的
			kcp.delSegment(*seg)
			count++
		} else {
			// snd_buf中的seg是按sn的顺序排列的
			break
		}
	}
	if count > 0 {
		// 将数据往前移动count位，前count个数据丢弃
		kcp.snd_buf = kcp.remove_front(kcp.snd_buf, count)
	}
}

// ack append
func (kcp *KCP) ack_push(sn, ts uint32) {
	kcp.acklist = append(kcp.acklist, ackItem{sn, ts})
}

// 根据segment.sn分析当前segment与rcv_buf中的那些segment的关系
// 1. 如果已经接收过了，则丢弃
// 2. 否则将其按sn的顺序插入到rcv_buf中对应的位置中去
// 3. 按顺序将sn连续在一起(通过跟rcv_nxt对比)的segment转移到rcv_queue中
func (kcp *KCP) parse_data(newseg segment) {
	sn := newseg.sn
	// 窗口在调用之前已经判断过了，不会命中这个条件
	if _itimediff(sn, kcp.rcv_nxt+kcp.rcv_wnd) >= 0 ||
		_itimediff(sn, kcp.rcv_nxt) < 0 {
		kcp.delSegment(newseg)
		return
	}

	n := len(kcp.rcv_buf) - 1
	insert_idx := 0
	repeat := false
	// 从后往前，seg本身就是逆序发过来的，这样更大概率循环更少
	// 找到插入位置
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
		// 重复的丢弃
		kcp.delSegment(newseg)
	}

	// move available data from rcv_buf -> rcv_queue
	count := 0
	for k := range kcp.rcv_buf {
		seg := &kcp.rcv_buf[k]
		// 这是这个判断保证了frg大的包一定会等到
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
	// 这个包还没有收到ack
	snd_una := kcp.snd_una
	if len(data) < IKCP_OVERHEAD {
		return -1
	}

	var maxack uint32
	var lastackts uint32
	var flag int
	var inSegs uint64

	// data中可能有多个segment
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
		data = ikcp_decode32u(data, &una) // 一端的rcv_nxt就是另一端的una
		data = ikcp_decode32u(data, &length)
		// 如上所言，data可能不止一个seg，这里的length是第一个seg的length，所以len(data) >= int(length)
		if len(data) < int(length) {
			return -2
		}

		if cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
			cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS {
			return -3
		}

		// only trust window updates from regular packets. i.e: latest update
		if regular {
			// 获得远端的窗口大小，每一个包都会带有wnd，所以是实时更新的
			kcp.rmt_wnd = uint32(wnd)
		}
		// 分析una，看哪些segment远端收到了，把远端收到的segment从snd_buf中移除
		// 注意：kcp所有报文类型均带有una信息。KCP 中同时使用了 UNA 以及 ACK 编号的报文确认手段。
		// UNA 表示此前所有的数据都已经被接收到，而 ACK 表示指定编号的数据包被接收到
		kcp.parse_una(una)
		// 更新kcp的una
		// 不能直接用这个una更新kcp的snd_una，可能收到之前的包，这时候una是偏小的
		kcp.shrink_buf()

		if cmd == IKCP_CMD_ACK {
			// 如果收到的是远端发来的ACK包

			// 分析具体是哪个segment被收到了，将其从snd_buf中移除
			// 同时给snd_buf中的其它segment的fastack字段增加计数++
			kcp.parse_ack(sn)
			// 因为snd_buf可能改变了，更新当前的snd_una
			kcp.shrink_buf()
			// 因为此时收到远端的ack，所以我们知道远端的包到本机的时间，因此可统计当前的网速如何，进行调整。这里是可以更新rto的，但是没有看到代码
			// 补充：在691行更新
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
				// 问：为什么不先判断sn与kcp.rcv_nxt的大小，再决定要不要发ack？
				// 答：可能就是之前ack丢失导致了对端的重发，所以针对每一个包都要ack
				kcp.ack_push(sn, ts)
				if _itimediff(sn, kcp.rcv_nxt) >= 0 {
					// 小于rcv_nxt的包肯定已经接受过了，大于的可能也接受过，下面会判断
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
					// 3. 按顺序将sn连续在一起(通过跟rcv_nxt对比)的segment转移到rcv_queue中
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
		// 根据当前收到的最大的ACK编号，在快重传的过程计算已发送的数据包被跳过的次数
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
	seg.wnd = kcp.wnd_unused() // 剩余接收窗口
	seg.una = kcp.rcv_nxt

	// buffer中不会有超过一个kcp.mtu
	buffer := kcp.buffer
	// flush acknowledges
	// 将前面收到数据时，压进ack发送队列的ack发送出去
	ptr := buffer
	for i, ack := range kcp.acklist {
		size := len(buffer) - len(ptr)
		// 为什么这里是加上一个IKCP_OVERHEAD来比较？
		// 因为ack包只有header，没有body, seg.encode之后的数据大小就是一个IKCP_OVERHEAD
		if size+IKCP_OVERHEAD > int(kcp.mtu) {
			// 下面两行将会一直出现，需要和seg.encode(ptr)一起理解
			// len(buffer) - len(ptr)表示的是可以发送的数据长度，在发送完毕后，ptr = buffer，将ptr指向了
			// buffer发送的开始位置，seg.encode(ptr)，在向底层的slice（buffer）写入数据，并将ptr往后移动，
			// 此函数执行完之后，可以保证ptr在数据的结尾处，ptr和buffer共用底层的数组。
			// 本质上是通过seg.encode(ptr)在不停地向buffer中填充数据
			kcp.output(buffer, size)
			ptr = buffer
		}
		// filter jitters caused by bufferbloat
		// kcp.rcv_nxt之前的包已经都收到了，但是为什么之前的ack就不发了呢？万一ack丢了呢？发送端是不是会一直
		// 重传，然而接收端永远不会ack？
		// 其实不然，发送方在发送时会判断窗口（下面发送的逻辑），如果窗口左边的那个包一直没有收到ack，发送方
		// 会停止发送这个包之后的数据，只重发这个包，在这里就会走到en(kcp.acklist)-1 == i的逻辑
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
				kcp.probe_wait += kcp.probe_wait / 2 // 延长探测间隔
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
	if (kcp.probe & IKCP_ASK_SEND) != 0 { // 需要探测远端窗口
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
		if _itimediff(kcp.snd_nxt, kcp.snd_una+cwnd) >= 0 {
			// 有一个很久之前的seg未被确认，不要再发送新的包，只处理snd_buffer中现有的
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
		// 前newSegsCount个seg已经发送，将后面的seg挪到前面来
		kcp.snd_queue = kcp.remove_front(kcp.snd_queue, newSegsCount)
	}

	// calculate resent
	// 获取快速重传设置
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
			// tcp也有这样的机制，参考 [Early Retransmit for TCP](https://tools.ietf.org/html/rfc5827)
			// 没有新的数据(从queue->buf)需要传输，并且seg已经延迟了（比之后发送的seg慢）
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
				// 现有数据size加上待发数据已经超过一个kcp.mtu，先发已存在的数据，
				// kcp保证一次发送的数据不要超过udp的mss
				kcp.output(buffer, size)
				current = currentMs() // time update for a blocking call
				ptr = buffer
			}

			ptr = segment.encode(ptr)
			// 上面的ptr已经不是以前的ptr了，他像一个指针，一步步往后挪，就和他的名字一样
			copy(ptr, segment.data)
			// ptr，指向数据的终点
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
//
// kcp需要上层通过update来驱动kcp数据包的发送，每次驱动的时间间隔由interval来决定，interval可以通过函数interval来设置，间隔时间在10毫秒到5秒之间，初始默认值为100毫秒。
// 另外注意到一点是，updated参数只有在第一次调用update函数时设置为1，源码中没有找到重置为0的地方，目测就是一个标志参数，用于区别第一次驱动和之后的驱动所需要选择的时间。
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
//
// check函数用于获取下次update的时间。具体的时间由上次update后更新的下次时间和snd_buf中的超时重传时间决定。
// check过程会寻找snd_buf中是否有超时重传的数据，如果有需要重传的Segment，将返回当前时间，立即进行一次update来进行重传，如果全都不需要重传，则会根据最小的重传时间来判断下次update的时间。
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
	newn := copy(q, q[n:]) // copy返回copy数据的个数，这里是len(q[n:])
	for i := newn; i < len(q); i++ {
		q[i] = segment{} // manual set nil for GC
	}
	return q[:newn]
}
