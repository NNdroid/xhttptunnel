package main

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"testing"

	"go.uber.org/zap"
)

// init 初始化一个 Nop Logger，防止在跑 Benchmark 时疯狂输出日志拖慢性能
func init() {
	logger = zap.NewNop()
	zap.ReplaceGlobals(logger)

	// 如果你的 sendBuf 是在 main.go 的 main 函数里初始化的，
	// 跑测试时可能会因为 nil 导致 panic，这里做一个兜底初始化
	if sendBuf.New == nil {
		sendBuf = sync.Pool{
			New: func() interface{} {
				b := make([]byte, 262144) // 默认 256KB
				return &b
			},
		}
	}
}

// ==========================================
// 1. 单元测试 (确保核心逻辑正确性)
// ==========================================

func TestReliableBuffer_Logic(t *testing.T) {
	rb := &reliableBuffer{}

	// 1. 写入数据
	rb.Write([]byte("hello world"))

	// 2. 获取数据 (尚未确认)
	// 【修复】：传入 ackedSeq=0, dispatchSeq=0, maxLen=5
	data, seq, _ := rb.GetSlice(0, 0, 5)
	if string(data) != "hello" || seq != 0 {
		t.Fatalf("Expected 'hello' at seq 0, got %q at %d", data, seq)
	}

	// 3. 模拟对端返回 Ack = 5 (确认收到了 'hello')
	// 滑动窗口应该向前移动，下一次获取应返回 ' world'
	// 【修复】：传入 ackedSeq=5, dispatchSeq=5, maxLen=100
	data2, seq2, _ := rb.GetSlice(5, 5, 100)
	if string(data2) != " world" || seq2 != 5 { // 注意空格
		t.Fatalf("Expected ' world' at seq 5, got %q at %d", data2, seq2)
	}

	// 4. 模拟 Ack 越界清空
	// 【修复】：传入 ackedSeq=11, dispatchSeq=11, maxLen=100
	rb.GetSlice(11, 11, 100)
	if rb.Len() != 0 {
		t.Fatalf("Buffer should be empty, len is %d", rb.Len())
	}
}

func TestMeekVirtualConn_PutReadData(t *testing.T) {
	vc := newMeekVirtualConn("test-session", nil, nil)

	// 测试正常按序到达
	ack := vc.PutReadData(0, []byte("part1-"))
	if ack != 6 || vc.readBuf.String() != "part1-" {
		t.Fatalf("Failed normal seq")
	}

	// 测试乱序/重传到达 (Seq 依然是 0，应该被静默丢弃，Ack 不变)
	ack2 := vc.PutReadData(0, []byte("part1-"))
	if ack2 != 6 || vc.readBuf.String() != "part1-" {
		t.Fatalf("Failed to drop duplicated packet")
	}

	// 测试后续包到达
	vc.PutReadData(6, []byte("part2"))
	if vc.readBuf.String() != "part1-part2" {
		t.Fatalf("Failed combined packet")
	}
}

// ==========================================
// 2. 性能基准测试 Benchmark
// ==========================================

// BenchmarkReliableBuffer_WriteAndAck 测试滑动窗口的吞吐性能
// 模拟高吞吐下不断追加数据并不断被 ACK 清理的场景
func BenchmarkReliableBuffer_WriteAndAck(b *testing.B) {
	rb := &reliableBuffer{}
	payload := make([]byte, 8192) // 8KB 块
	rand.Read(payload)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	var acked uint64 = 0
	for i := 0; i < b.N; i++ {
		rb.Write(payload)

		// 模拟每写一次，对端 Ack 确认了这部分数据 (完全滑动)
		acked += uint64(len(payload))
		// 【修复】：参数对齐并发版签名
		rb.GetSlice(acked, acked, 8192)
	}
}

// BenchmarkMeekVirtualConn_PutRead 测试带 Seq 校验的数据接收性能
func BenchmarkMeekVirtualConn_PutRead(b *testing.B) {
	vc := newMeekVirtualConn("bench-session", nil, nil)
	payload := make([]byte, 4096)
	rand.Read(payload)

	// 启动一个后台 Goroutine 疯狂消费 Read，防止 Buffer 撑爆内存
	go func() {
		buf := make([]byte, 8192)
		for !vc.closed {
			vc.Read(buf)
		}
	}()
	defer vc.Close()

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	var seq uint64 = 0
	for i := 0; i < b.N; i++ {
		vc.PutReadData(seq, payload)
		seq += uint64(len(payload))
	}
}

// BenchmarkXHTTPFramedConn_Write 测试带动态 Padding 和流量混淆的写出性能
func BenchmarkXHTTPFramedConn_Write(b *testing.B) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	fc := newXhttpFramedConn(client, client, func() error { return nil }, nil, nil)
	payload := make([]byte, 16384) // 接近框架最大 Payload
	rand.Read(payload)

	go func() {
		buf := make([]byte, 32768)
		for {
			_, err := server.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		fc.Write(payload)
	}
}

// BenchmarkXHTTPFramedConn_Read 测试解包与 Padding 丢弃机制的性能
func BenchmarkXHTTPFramedConn_Read(b *testing.B) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	fc := newXhttpFramedConn(server, server, func() error { return nil }, nil, nil)
	payload := make([]byte, 4096)

	// 预先准备好带有 Padding 的帧流注入给客户端
	go func() {
		// 手动模拟 xhttpFramedConn.Write 的逻辑 (需适配全新的 6 字节头协议)
		for {
			chunkSize := len(payload)
			padLen := 32                       // 固定的 Padding
			frameLen := 6 + padLen + chunkSize // ✅ 使用 6 字节头部
			frame := make([]byte, frameLen)

			// ✅ 使用 uint32 写入 4 字节 Payload Length
			binary.BigEndian.PutUint32(frame[0:4], uint32(chunkSize))
			// ✅ 使用 uint16 写入 2 字节 Padding Length
			binary.BigEndian.PutUint16(frame[4:6], uint16(padLen))

			_, err := client.Write(frame)
			if err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 8192)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 每次 Read 必定会解开一层 Frame
		fc.Read(buf)
	}
}

// BenchmarkFullMemoryE2E 测试纯内存管道下的端到端双向 Copy (极致压力测试)
func BenchmarkFullMemoryE2E(b *testing.B) {
	c1, s1 := net.Pipe()
	defer c1.Close()
	defer s1.Close()

	fcClient := newXhttpFramedConn(c1, c1, func() error { return nil }, nil, nil)
	fcServer := newXhttpFramedConn(s1, s1, func() error { return nil }, nil, nil)

	payload := make([]byte, 8192)
	rand.Read(payload)

	var wg sync.WaitGroup
	wg.Add(1)

	// Server 端 Echo 逻辑
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := fcServer.Read(buf)
			if err != nil {
				return
			}
			fcServer.Write(buf[:n])
		}
	}()

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	recvBuf := make([]byte, 8192)
	for i := 0; i < b.N; i++ {
		// 客户端发多少
		fcClient.Write(payload)

		// 客户端收多少 (Echo)
		readTotal := 0
		for readTotal < len(payload) {
			n, _ := fcClient.Read(recvBuf)
			readTotal += n
		}
	}

	b.StopTimer()
	c1.Close()
	s1.Close()
	wg.Wait()
}
