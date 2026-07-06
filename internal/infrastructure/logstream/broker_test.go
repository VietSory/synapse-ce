package logstream

import (
	"testing"
)

func TestPublishThenLiveTail(t *testing.T) {
	b := NewBroker(0)
	ch, cancel := b.Subscribe("run1", 0)
	defer cancel()

	b.Publish("run1", "line one")
	b.Publish("run1", "line two")

	e1 := <-ch
	e2 := <-ch
	if e1.Line != "line one" || e1.ID != 1 {
		t.Errorf("e1 = %+v", e1)
	}
	if e2.Line != "line two" || e2.ID != 2 {
		t.Errorf("e2 = %+v", e2)
	}
}

func TestReconnectReplaysAfterID(t *testing.T) {
	b := NewBroker(0)
	b.Publish("run1", "one")
	b.Publish("run1", "two")
	b.Publish("run1", "three")

	// Reconnect having already seen event id 1: should replay 2 and 3.
	ch, cancel := b.Subscribe("run1", 1)
	defer cancel()

	e := <-ch
	if e.ID != 2 || e.Line != "two" {
		t.Fatalf("first replayed = %+v, want id2", e)
	}
	e = <-ch
	if e.ID != 3 || e.Line != "three" {
		t.Fatalf("second replayed = %+v, want id3", e)
	}
}

func TestCloseEndsStream(t *testing.T) {
	b := NewBroker(0)
	ch, _ := b.Subscribe("run1", 0)
	b.Publish("run1", "working")
	b.Close("run1")

	var sawDone, chClosed bool
	for e := range ch {
		if e.Done {
			sawDone = true
		}
	}
	chClosed = true // range exits only when the channel is closed
	if !sawDone {
		t.Error("expected a Done event before close")
	}
	if !chClosed {
		t.Error("channel should be closed after Close")
	}
}

func TestSubscribeAfterCloseReplaysAndDone(t *testing.T) {
	b := NewBroker(0)
	b.Publish("run1", "history")
	b.Close("run1")

	ch, _ := b.Subscribe("run1", 0)
	var lines int
	var done bool
	for e := range ch {
		if e.Done {
			done = true
		} else if e.Line != "" {
			lines++
		}
	}
	if lines != 1 || !done {
		t.Errorf("want 1 history line + Done, got lines=%d done=%v", lines, done)
	}
}
