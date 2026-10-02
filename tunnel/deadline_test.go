package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

func TestDeadlineReadResumesPartialFrame(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var wire bytes.Buffer
		writer := newXHTTPConn(nil, &wire, nil, nil, nil, nil)
		payload := []byte("resume a frame after a deadline")
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
		encoded := wire.Bytes()
		vc := newMeekVirtualConn("deadline", nil, nil, nil)
		defer vc.Close()
		conn := newXHTTPConn(vc, vc, vc.Close, nil, nil, vc)
		padding := int(binary.BigEndian.Uint16(encoded[4:6]))
		cuts := []int{3, 6 + padding/2, 6 + padding}
		seq := 0
		for _, cut := range cuts {
			vc.PutReadData(uint64(seq), encoded[seq:cut])
			seq = cut
			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { var b [64]byte; _, err := conn.Read(b[:]); done <- err }()
			synctest.Wait()
			time.Sleep(time.Second)
			synctest.Wait()
			if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("read: %v", err)
			}
			if err := conn.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
		}
		vc.PutReadData(uint64(seq), encoded[seq:])
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload corrupted: %q", got)
		}
	})
}

func TestDeadlineWriteLeavesNoPartialFrame(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		vc := newMeekVirtualConn("deadline", nil, nil, nil)
		vc.writeBuf = newReliableBuffer(4096)
		defer vc.Close()
		_, _ = vc.Write(make([]byte, 4096))
		conn := newXHTTPConn(vc, vc, vc.Close, nil, nil, vc)
		if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			n, err := conn.Write([]byte("hello"))
			if n != 0 {
				t.Errorf("timed-out frame accepted %d payload bytes", n)
			}
			done <- err
		}()
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("write: %v", err)
		}
		if vc.writeBuf.Len() != 4096 {
			t.Fatal("timeout published a partial frame")
		}
		vc.writeBuf.acknowledge(4096)
		if err := conn.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		frame, _, ptr := vc.writeBuf.GetSlice(4096, 4096, 4096)
		defer safelyPutSendBuf(ptr)
		reader := newXHTTPConn(bytes.NewReader(frame), nil, nil, nil, nil, nil)
		got := make([]byte, 5)
		if _, err := io.ReadFull(reader, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != "hello" {
			t.Fatalf("retry corrupted frame: %q", got)
		}
	})
}

func TestReliableBufferBlockedWriteStops(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		for _, closeBuffer := range []bool{false, true} {
			t.Run(fmt.Sprintf("oversized=%v/close=%v", oversized, closeBuffer), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					rb := newReliableBuffer(4)
					defer rb.Close()
					if _, err := rb.Write([]byte("seed")); err != nil {
						t.Fatal(err)
					}
					payload := []byte("abc")
					if oversized {
						payload = []byte("abcdef")
					}
					result := make(chan error, 1)
					go func() {
						n, err := rb.Write(payload)
						if n != 0 {
							t.Errorf("blocked write accepted %d bytes", n)
						}
						result <- err
					}()
					synctest.Wait()
					want := error(os.ErrDeadlineExceeded)
					if closeBuffer {
						want = io.ErrClosedPipe
						rb.Close()
					} else {
						rb.setWriteDeadline(time.Now().Add(time.Second))
						time.Sleep(time.Second)
					}
					synctest.Wait()
					if err := <-result; !errors.Is(err, want) {
						t.Fatalf("write error: %v, want %v", err, want)
					}
				})
			})
		}
	}
}

func TestDeadlineChangedWhileBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		vc := newMeekVirtualConn("deadline", nil, nil, nil)
		defer vc.Close()
		done := make(chan error, 1)
		go func() { var b [1]byte; _, err := vc.Read(b[:]); done <- err }()
		synctest.Wait()
		_ = vc.SetReadDeadline(time.Now().Add(time.Hour))
		_ = vc.SetReadDeadline(time.Now().Add(time.Second))
		time.Sleep(time.Second)
		synctest.Wait()
		if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read: %v", err)
		}
	})
}

func TestCloseDrainTimeoutWithoutDispatcher(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rb := newReliableBuffer(4096)
		_, _ = rb.Write([]byte("undispatched"))
		done := make(chan struct{})
		go func() { rb.waitDrained(time.Second, 0); close(done) }()
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("drain timeout did not release the waiter")
		}
		rb.Close()
	})
}

func TestDeadlineReadRetainsPayloadSuffix(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var wire bytes.Buffer
		payload := []byte("partial payload followed by buffered suffix")
		writer := newXHTTPConn(nil, &wire, nil, nil, nil, nil)
		_, _ = writer.Write(payload)
		encoded := wire.Bytes()
		cut := 6 + int(binary.BigEndian.Uint16(encoded[4:6])) + 10
		vc := newMeekVirtualConn("partial", nil, nil, nil)
		defer vc.Close()
		conn := newXHTTPConn(vc, vc, vc.Close, nil, nil, vc)
		vc.PutReadData(0, encoded[:cut])
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		got := make([]byte, 5)
		done := make(chan error, 1)
		go func() {
			n, err := conn.Read(got)
			if n != 5 {
				t.Errorf("accepted %d bytes, want 5", n)
			}
			done <- err
		}()
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read error: %v", err)
		}
		_ = conn.SetReadDeadline(time.Time{})
		vc.PutReadData(uint64(cut), encoded[cut:])
		tail := make([]byte, len(payload)-5)
		if _, err := io.ReadFull(conn, tail); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(append(got, tail...), payload) {
			t.Fatal("partial timeout lost payload bytes")
		}
	})
}
