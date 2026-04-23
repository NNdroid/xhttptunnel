package main

import (
	"sync"
	"testing"
	"time"
)

// 初始化測試用的記憶體池，防止 GetSlice 時出現 nil pointer panic
func init() {
	if sendBuf.New == nil {
		sendBuf.New = func() interface{} {
			b := make([]byte, 1024*1024) // 測試用 1MB
			return &b
		}
	}
}

// 測試 1：基礎的寫入與讀取邏輯
func TestReliableBuffer_BasicWriteAndRead(t *testing.T) {
	rb := newReliableBuffer(1024)

	// 1. 測試寫入
	data := []byte("hello world")
	n, err := rb.Write(data)
	if err != nil || n != len(data) {
		t.Fatalf("寫入失敗: expected %d, got %d, err: %v", len(data), n, err)
	}

	if rb.Len() != len(data) {
		t.Fatalf("長度錯誤: expected %d, got %d", len(data), rb.Len())
	}

	// 2. 測試讀取 (模擬 Seq = 0, dispatch = 0)
	slice, nextSeq, bufPtr := rb.GetSlice(0, 0, 100)
	if string(slice) != "hello world" {
		t.Fatalf("讀取內容錯誤: expected 'hello world', got '%s'", string(slice))
	}
	if nextSeq != 0 {
		t.Fatalf("返回的派發起點錯誤: expected 0, got %d", nextSeq)
	}

	// 歸還記憶體池
	if bufPtr != nil {
		sendBuf.Put(bufPtr)
	}
}

// 測試 2：核心場景 —— 環形邊界繞回 (Wraparound) 測試
func TestReliableBuffer_Wraparound(t *testing.T) {
	// 故意設定一個很小的容量 (5 bytes)
	rb := newReliableBuffer(5)

	// 1. 寫入 3 bytes
	rb.Write([]byte("123"))

	// 2. 模擬對端 Ack 了這 3 bytes，這會推進 tail，並空出前面的空間
	rb.GetSlice(3, 3, 5) // remoteAck = 3，推進 baseOffset 到 3
	if rb.Len() != 0 {
		t.Fatalf("Ack 清理失敗: expected 0, got %d", rb.Len())
	}

	// 3. 再寫入 4 bytes "4567"。
	// 因為容量只有 5，目前 head 在 index 3，所以這 4 bytes 會被切成兩半：
	// "45" 寫在結尾 (index 3, 4)，"67" 繞回到開頭 (index 0, 1)
	n, err := rb.Write([]byte("4567"))
	if err != nil || n != 4 {
		t.Fatalf("環形寫入失敗: expected 4, got %d", n)
	}

	if rb.Len() != 4 {
		t.Fatalf("環形寫入後長度錯誤: expected 4, got %d", rb.Len())
	}

	// 4. 進行環形讀取測試 (此時 dispatchSeq 應該為 3)
	slice, _, bufPtr := rb.GetSlice(3, 3, 5)
	if string(slice) != "4567" {
		t.Fatalf("環形讀取錯誤: expected '4567', got '%s'", string(slice))
	}

	if bufPtr != nil {
		sendBuf.Put(bufPtr)
	}
}

// 測試 3：亂序重傳與游標偏移量測試
func TestReliableBuffer_DispatchOffset(t *testing.T) {
	rb := newReliableBuffer(20)
	rb.Write([]byte("abcdefghij")) // 10 bytes

	// 模擬對端確認了前 3 個 bytes (Ack = 3)，但我們需要從第 5 個 byte 開始發送 (模擬中間丟包，局部重傳)
	// baseOffset 會變成 3，資料剩下 "defghij"
	slice, _, bufPtr := rb.GetSlice(3, 5, 10)

	// dispatchSeq 為 5，對應的資料應該是從 'f' 開始
	if string(slice) != "fghij" {
		t.Fatalf("偏移量讀取錯誤: expected 'fghij', got '%s'", string(slice))
	}

	if bufPtr != nil {
		sendBuf.Put(bufPtr)
	}
}

// 測試 4：併發控制與阻塞喚醒 (Backpressure) 測試
func TestReliableBuffer_BlockingAndWakeup(t *testing.T) {
	rb := newReliableBuffer(10)

	// 先寫滿 8 bytes
	rb.Write([]byte("12345678"))

	var wg sync.WaitGroup
	wg.Add(1)

	// 啟動一個 Goroutine 嘗試寫入 5 bytes
	// 因為 8 + 5 > 10，所以這個 Goroutine 一定會被 Wait() 阻塞
	writeDone := make(chan struct{})
	go func() {
		defer wg.Done()
		rb.Write([]byte("abcde"))
		close(writeDone)
	}()

	// 給 Goroutine 一點時間進入阻塞狀態
	time.Sleep(100 * time.Millisecond)

	select {
	case <-writeDone:
		t.Fatal("寫入提早完成了，沒有正確阻塞！")
	default:
		// 正常，還在阻塞中
	}

	// 模擬對端發來 Ack = 5，清理掉前 5 bytes，騰出空間！
	// GetSlice 內部發現 freed == true，會觸發 rb.cond.Broadcast()
	rb.GetSlice(5, 5, 10)

	// 等待 Goroutine 被喚醒並完成寫入
	select {
	case <-writeDone:
		// 成功被喚醒並寫入完成
	case <-time.After(1 * time.Second):
		t.Fatal("Goroutine 沒有被正確喚醒！")
	}

	// 驗證最終殘留的資料
	// 原本 8 bytes，Ack 5 後剩 "678" (3 bytes)
	// 被喚醒後寫入 "abcde" (5 bytes)
	// 總長度應為 8
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

// 測試 5：強制關閉測試
func TestReliableBuffer_Close(t *testing.T) {
	rb := newReliableBuffer(5)
	rb.Write([]byte("123"))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// 故意寫入過大的資料讓它阻塞
		_, err := rb.Write([]byte("45678"))
		if err == nil {
			t.Error("Close 後應該返回錯誤，但返回了 nil")
		}
	}()

	time.Sleep(50 * time.Millisecond)

	// 關閉緩衝區，必須能立刻喚醒並中斷上面的 Goroutine
	rb.Close()
	wg.Wait()
}
