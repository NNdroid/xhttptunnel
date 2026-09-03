package main

import (
	"sync"
	"testing"
	"time"
)

// Initialize the test memory pool to avoid a nil pointer panic in GetSlice.
func init() {
	if sendBuf.New == nil {
		sendBuf.New = func() interface{} {
			b := make([]byte, 1024*1024) // 1MB for tests
			return &b
		}
	}
}

// Test 1: basic write and read logic
func TestReliableBuffer_BasicWriteAndRead(t *testing.T) {
	rb := newReliableBuffer(1024)

	// 1. Test writing
	data := []byte("hello world")
	n, err := rb.Write(data)
	if err != nil || n != len(data) {
		t.Fatalf("寫入失敗: expected %d, got %d, err: %v", len(data), n, err)
	}

	if rb.Len() != len(data) {
		t.Fatalf("長度錯誤: expected %d, got %d", len(data), rb.Len())
	}

	// 2. Test reading (with Seq = 0, dispatch = 0)
	slice, nextSeq, bufPtr := rb.GetSlice(0, 0, 100)
	if string(slice) != "hello world" {
		t.Fatalf("讀取內容錯誤: expected 'hello world', got '%s'", string(slice))
	}
	if nextSeq != 0 {
		t.Fatalf("返回的派發起點錯誤: expected 0, got %d", nextSeq)
	}

	// Return the buffer to the pool
	if bufPtr != nil {
		sendBuf.Put(bufPtr)
	}
}

// Test 2: core scenario — ring boundary wraparound
func TestReliableBuffer_Wraparound(t *testing.T) {
	// Deliberately use a tiny capacity (5 bytes)
	rb := newReliableBuffer(5)

	// 1. Write 3 bytes
	rb.Write([]byte("123"))

	// 2. Simulate the peer acknowledging those 3 bytes: this advances tail
	// and frees the space at the front
	rb.GetSlice(3, 3, 5) // remoteAck = 3, advances baseOffset to 3
	if rb.Len() != 0 {
		t.Fatalf("Ack 清理失敗: expected 0, got %d", rb.Len())
	}

	// 3. Write 4 more bytes "4567".
	// With a capacity of 5 and head at index 3, these 4 bytes get split in half:
	// "45" goes at the end (index 3, 4) and "67" wraps around to the front (index 0, 1)
	n, err := rb.Write([]byte("4567"))
	if err != nil || n != 4 {
		t.Fatalf("環形寫入失敗: expected 4, got %d", n)
	}

	if rb.Len() != 4 {
		t.Fatalf("環形寫入後長度錯誤: expected 4, got %d", rb.Len())
	}

	// 4. Perform a wraparound read (dispatchSeq should now be 3)
	slice, _, bufPtr := rb.GetSlice(3, 3, 5)
	if string(slice) != "4567" {
		t.Fatalf("環形讀取錯誤: expected '4567', got '%s'", string(slice))
	}

	if bufPtr != nil {
		sendBuf.Put(bufPtr)
	}
}

// Test 3: out-of-order retransmission and cursor offset
func TestReliableBuffer_DispatchOffset(t *testing.T) {
	rb := newReliableBuffer(20)
	rb.Write([]byte("abcdefghij")) // 10 bytes

	// Simulate the peer acknowledging the first 3 bytes (Ack = 3) while we need
	// to send starting from the 5th byte (simulating a lost middle packet, partial retransmit)
	// baseOffset becomes 3 and the remaining data is "defghij"
	slice, _, bufPtr := rb.GetSlice(3, 5, 10)

	// dispatchSeq is 5, so the data should start from 'f'
	if string(slice) != "fghij" {
		t.Fatalf("偏移量讀取錯誤: expected 'fghij', got '%s'", string(slice))
	}

	if bufPtr != nil {
		sendBuf.Put(bufPtr)
	}
}

// Test 4: concurrency control and blocking wakeup (backpressure)
func TestReliableBuffer_BlockingAndWakeup(t *testing.T) {
	rb := newReliableBuffer(10)

	// First fill up 8 bytes
	rb.Write([]byte("12345678"))

	var wg sync.WaitGroup
	wg.Add(1)

	// Start a goroutine that tries to write 5 bytes.
	// Since 8 + 5 > 10, this goroutine must block in Wait().
	writeDone := make(chan struct{})
	go func() {
		defer wg.Done()
		rb.Write([]byte("abcde"))
		close(writeDone)
	}()

	// Give the goroutine some time to enter the blocked state
	time.Sleep(100 * time.Millisecond)

	select {
	case <-writeDone:
		t.Fatal("寫入提早完成了，沒有正確阻塞！")
	default:
		// Normal, still blocked
	}

	// Simulate the peer sending Ack = 5: clears the first 5 bytes and frees space!
	// GetSlice detects freed == true internally and triggers rb.cond.Broadcast()
	rb.GetSlice(5, 5, 10)

	// Wait for the goroutine to be woken up and finish the write
	select {
	case <-writeDone:
		// Successfully woken up, write completed
	case <-time.After(1 * time.Second):
		t.Fatal("Goroutine 沒有被正確喚醒！")
	}

	// Verify the final remaining data:
	// originally 8 bytes, after Ack 5 the remainder is "678" (3 bytes);
	// after wakeup, "abcde" (5 bytes) was written;
	// the total length should be 8
	if rb.Len() != 8 {
		t.Fatalf("喚醒後資料長度錯誤: expected 8, got %d", rb.Len())
	}

	slice, _, bufPtr := rb.GetSlice(5, 5, 10)
	if string(slice) != "678abcde" {
		t.Fatalf("喚醒後資料內容錯誤: expected '678abcde', got '%s'", string(slice))
	}
	if bufPtr != nil {
		sendBuf.Put(bufPtr)
	}
}

// Test 5: forced close
func TestReliableBuffer_Close(t *testing.T) {
	rb := newReliableBuffer(5)
	rb.Write([]byte("123"))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Deliberately write oversized data so it blocks
		_, err := rb.Write([]byte("45678"))
		if err == nil {
			t.Error("Close 後應該返回錯誤，但返回了 nil")
		}
	}()

	time.Sleep(50 * time.Millisecond)

	// Close the buffer; it must immediately wake up and interrupt the goroutine above
	rb.Close()
	wg.Wait()
}

// Test 6: concurrent Close vs PutReadData race (guards against a nil map panic)
func TestMeekVirtualConn_ConcurrentClosePutReadData(t *testing.T) {
	conn := newMeekVirtualConn("test-race", stringAddr("127.0.0.1:1"), stringAddr("127.0.0.1:2"))
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				conn.PutReadData(uint64(idx*100+j), []byte("race-test-data"))
			}
		}(i)
	}

	time.Sleep(10 * time.Millisecond)
	_ = conn.Close()
	wg.Wait()
	t.Log("✅ 併發關閉下 PutReadData 零 Panic 成功通過！")
}

// Test 7: reassembly-buffer backpressure. Once the in-order reassembly buffer
// hits maxReassemblyBytes, a further contiguous chunk must block in
// waitForReassemblyRoom until a reader drains room — not drop or overwrite.
func TestMeekVirtualConn_ReassemblyBackpressure(t *testing.T) {
	conn := newMeekVirtualConn("bp-reasm", stringAddr("127.0.0.1:1"), stringAddr("127.0.0.1:2"))

	// Fill the reassembly buffer to exactly the cap. The first chunk fits
	// without blocking.
	big := make([]byte, maxReassemblyBytes)
	if ack := conn.PutReadData(0, big); ack != uint64(maxReassemblyBytes) {
		t.Fatalf("first fill returned wrong ack: got %d, want %d", ack, maxReassemblyBytes)
	}
	if conn.readBuf.Len() != maxReassemblyBytes {
		t.Fatalf("reassembly buffer should be full, got %d", conn.readBuf.Len())
	}

	// A contiguous tail chunk must now park until the reader makes room.
	tail := make([]byte, 1)
	blocked := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(blocked)
		conn.PutReadData(uint64(maxReassemblyBytes), tail)
		close(done)
	}()

	<-blocked
	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("producer did not block on a full reassembly buffer")
	default:
	}

	// Drain one byte; the producer must wake and complete.
	buf := make([]byte, 1)
	if n, err := conn.Read(buf); n != 1 || err != nil {
		t.Fatalf("Read returned %d/%v", n, err)
	}
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("producer was not woken after a reader drained room")
	}

	// The held-back tail byte must now be readable.
	if n, _ := conn.Read(buf); n != 1 {
		t.Fatalf("tail byte not delivered, got %d", n)
	}
	_ = conn.Close()
}

// Test 8: out-of-order cache backpressure. Filling the cache to its chunk cap
// must block the next out-of-order PutReadData in waitForOutOfOrderRoom; it
// must wake once a leading chunk frees a slot and drainContiguous flushes the
// run.
func TestMeekVirtualConn_OutOfOrderBackpressure(t *testing.T) {
	conn := newMeekVirtualConn("bp-ooo", stringAddr("127.0.0.1:1"), stringAddr("127.0.0.1:2"))

	chunk := make([]byte, 1024)
	// 1024 strictly-ahead chunks fill the cache to its chunk cap.
	for i := 1; i <= maxOutOfOrderChunks; i++ {
		seq := uint64(i) * uint64(len(chunk))
		if ack := conn.PutReadData(seq, chunk); ack != 0 {
			t.Fatalf("out-of-order PutReadData must not advance ack, got %d", ack)
		}
	}
	if len(conn.oooBuf) != maxOutOfOrderChunks {
		t.Fatalf("ooo cache should be full, got %d", len(conn.oooBuf))
	}

	// The 1025th out-of-order chunk must block.
	extra := make([]byte, 1024)
	extraSeq := uint64(maxOutOfOrderChunks+1) * uint64(len(chunk))
	blocked := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(blocked)
		conn.PutReadData(extraSeq, extra)
		close(done)
	}()

	<-blocked
	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("producer did not block on a full out-of-order cache")
	default:
	}

	// Deliver the missing leading chunk; drainContiguous flushes the whole run,
	// a slot frees, and the parked producer must wake.
	if ack := conn.PutReadData(0, make([]byte, 1024)); ack == 0 {
		t.Fatal("leading chunk must advance the ack")
	}
	// No `default:` here — it would make this select non-blocking and the
	// assertion below could never fire, turning the test into a no-op that
	// passes no matter how the producer behaves.
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("producer was not woken after an ooo slot freed up")
	}

	// The parked chunk's gap was filled while it waited, so on wake it is
	// contiguous and must be delivered through readBuf. Filing it in oooBuf
	// instead would strand it there forever — drainContiguous only ever
	// inspects oooBuf[nextReadSeq], which has already moved past it.
	conn.readCond.L.Lock()
	stranded := len(conn.oooBuf)
	conn.readCond.L.Unlock()
	if stranded != 0 {
		t.Fatalf("woken chunk was stranded in the ooo cache (%d entries); it should have been delivered contiguously", stranded)
	}
	_ = conn.Close()
}
