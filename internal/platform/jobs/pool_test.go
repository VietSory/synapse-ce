package jobs

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolRunsAllTasks(t *testing.T) {
	p := NewPool(3, 16)
	defer p.Shutdown(context.Background())

	var ran int64
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		if err := p.Submit(func(context.Context) {
			defer wg.Done()
			atomic.AddInt64(&ran, 1)
		}); err != nil {
			t.Fatalf("submit: %v", err)
		}
	}
	wg.Wait()
	if ran != 10 {
		t.Errorf("ran %d tasks, want 10", ran)
	}
}

func TestPoolRespectsConcurrencyCap(t *testing.T) {
	const workers = 2
	p := NewPool(workers, 32)
	defer p.Shutdown(context.Background())

	var mu sync.Mutex
	var cur, max int
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		_ = p.Submit(func(context.Context) {
			defer wg.Done()
			mu.Lock()
			cur++
			if cur > max {
				max = cur
			}
			mu.Unlock()
			time.Sleep(2 * time.Millisecond)
			mu.Lock()
			cur--
			mu.Unlock()
		})
	}
	wg.Wait()
	if max > workers {
		t.Errorf("observed %d concurrent tasks, cap is %d", max, workers)
	}
	if max == 0 {
		t.Error("no tasks ran")
	}
}

func TestPoolQueueFull(t *testing.T) {
	p := NewPool(1, 1)
	defer p.Shutdown(context.Background())

	block := make(chan struct{})
	// Occupy the single worker.
	_ = p.Submit(func(context.Context) { <-block })
	// Fill the single queue slot (may need a beat for the worker to pick up the first).
	time.Sleep(10 * time.Millisecond)
	_ = p.Submit(func(context.Context) { <-block })

	if err := p.Submit(func(context.Context) {}); err != ErrQueueFull {
		t.Errorf("want ErrQueueFull, got %v", err)
	}
	close(block)
}

func TestPoolSubmitAfterShutdown(t *testing.T) {
	p := NewPool(2, 4)
	p.Shutdown(context.Background())
	if err := p.Submit(func(context.Context) {}); err != ErrStopped {
		t.Errorf("want ErrStopped, got %v", err)
	}
}

// TestPoolSubmitDuringShutdown asserts Submit racing Shutdown never panics with
// "send on closed channel" (run with -race). Submit must return cleanly (nil,
// ErrQueueFull, or ErrStopped) regardless of interleaving.
func TestPoolSubmitDuringShutdown(t *testing.T) {
	for i := 0; i < 50; i++ {
		p := NewPool(2, 4)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				err := p.Submit(func(context.Context) {})
				if err != nil && err != ErrQueueFull && err != ErrStopped {
					t.Errorf("unexpected submit error: %v", err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			p.Shutdown(context.Background())
		}()
		wg.Wait()
	}
}
