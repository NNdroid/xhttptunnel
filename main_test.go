package main

import (
	"crypto/rand"
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
	rb := newReliableBuffer(1024)

	// 1. 写入数据
	rb.Write([]byte("hello world"))

	// 2. 获取数据 (尚未确认)
	// 传入 ackedSeq=0, dispatchSeq=0, maxLen=5
	data, seq, _ := rb.GetSlice(0, 0, 5)
	if string(data) != "hello" || seq != 0 {
		t.Fatalf("Expected 'hello' at seq 0, got %q at %d", data, seq)
	}

	// 3. 模拟对端返回 Ack = 5 (确认收到了 'hello')
	// 滑动窗口应该向前移动，下一次获取应返回 ' world'
	// 传入 ackedSeq=5, dispatchSeq=5, maxLen=100
	data2, seq2, _ := rb.GetSlice(5, 5, 100)
	if string(data2) != " world" || seq2 != 5 { // 注意空格
		t.Fatalf("Expected ' world' at seq 5, got %q at %d", data2, seq2)
	}

	// 4. 模拟 Ack 越界清空
	// 传入 ackedSeq=11, dispatchSeq=11, maxLen=100
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
// 基準測試：Ring Buffer 極限效能測試
// 執行指令：go test -bench=BenchmarkReliableBuffer -benchmem -v
// ==========================================

// BenchmarkReliableBuffer_WriteOnly 測試純寫入效能 (無讀取)
func BenchmarkReliableBuffer_WriteOnly(b *testing.B) {
	rb := newReliableBuffer(10 * 1024 * 1024) // 10MB 緩衝區
	payload := make([]byte, 4096)             // 4KB payload
	rand.Read(payload)

	b.SetBytes(4096)
	b.ReportAllocs() // 開啟記憶體分配追蹤
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 每次寫滿前手動清理，模擬對端瞬間 ACK
		if rb.Len() >= rb.maxSize-4096 {
			rb.mu.Lock()
			rb.tail = rb.head
			rb.count = 0
			rb.mu.Unlock()
		}
		_, _ = rb.Write(payload)
	}
}

// BenchmarkReliableBuffer_Sequential_1KB 模擬高頻碎小封包 (如 SSH 敲擊、心跳包)
func BenchmarkReliableBuffer_Sequential_1KB(b *testing.B) {
	rb := newReliableBuffer(4 * 1024 * 1024) // 4MB
	payload := make([]byte, 1024)            // 1KB 小包
	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	var ack uint64 = 0
	var dispatch uint64 = 0

	for i := 0; i < b.N; i++ {
		// 1. 寫入
		n, _ := rb.Write(payload)

		// 2. 讀取並推進 Ack
		slice, nextSeq, bufPtr := rb.GetSlice(ack, dispatch, 1024)

		ack += uint64(n)
		dispatch = nextSeq

		// 歸還記憶體池 (模擬實際程式碼的運作)
		if bufPtr != nil {
			// 如果你的 pool 變數名稱不同，請替換為你的真實 pool
			sendBuf.Put(bufPtr)
		}

		_ = slice // 避免編譯器優化掉
	}
}

// BenchmarkReliableBuffer_Sequential_512KB 模擬大流量傳輸 (如 SFTP 下載、看影片)
func BenchmarkReliableBuffer_Sequential_512KB(b *testing.B) {
	rb := newReliableBuffer(4 * 1024 * 1024) // 4MB
	payload := make([]byte, 512*1024)        // 512KB 大包
	b.SetBytes(512 * 1024)
	b.ReportAllocs()
	b.ResetTimer()

	var ack uint64 = 0
	var dispatch uint64 = 0

	for i := 0; i < b.N; i++ {
		n, _ := rb.Write(payload)

		slice, nextSeq, bufPtr := rb.GetSlice(ack, dispatch, 512*1024)

		ack += uint64(n)
		dispatch = nextSeq

		if bufPtr != nil {
			sendBuf.Put(bufPtr)
		}
		_ = slice
	}
}

// BenchmarkReliableBuffer_Wraparound 壓力測試：跨越陣列邊界的環形拷貝效能
func BenchmarkReliableBuffer_Wraparound(b *testing.B) {
	// 🚀 關鍵：Buffer (2MB) 必須大於 Payload 的兩倍 (1.6MB)，防止單執行緒死結
	rb := newReliableBuffer(2 * 1024 * 1024)
	payload := make([]byte, 800*1024) // 800KB Payload

	b.SetBytes(800 * 1024)
	b.ReportAllocs()
	b.ResetTimer()

	var ack uint64 = 0
	var dispatch uint64 = 0

	for i := 0; i < b.N; i++ {
		// 1. 寫入 800KB
		n, _ := rb.Write(payload)

		// 2. 讀出並清理上一回合的資料
		slice, nextSeq, bufPtr := rb.GetSlice(ack, dispatch, 800*1024)

		// 3. 推進確認號碼
		ack += uint64(n)
		dispatch = nextSeq

		// 4. 安全歸還記憶體池
		if bufPtr != nil {
			sendBuf.Put(bufPtr)
		}
		_ = slice
	}
}
