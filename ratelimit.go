package authkit

import (
	"math"
	"sync"
	"time"
)

// rateLimiter is a token bucket per client address, held in memory. It is
// per process, which is right for one replica; behind several replicas the
// effective limit is multiplied.
type rateLimiter struct {
	now     func() time.Time
	buckets map[string]*bucket
	swept   time.Time
	perSec  float64
	burst   float64
	mu      sync.Mutex
}

type bucket struct {
	updated time.Time
	tokens  float64
}

func newRateLimiter(perMinute, burst int, now func() time.Time) *rateLimiter {
	return &rateLimiter{
		now:     now,
		buckets: map[string]*bucket{},
		perSec:  float64(perMinute) / 60,
		burst:   float64(burst),
	}
}

// allow spends one token for key. When there is none it returns the number
// of seconds until there will be.
func (l *rateLimiter) allow(key string) (retryAfter int, ok bool) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now)
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, updated: now}
		l.buckets[key] = b
	}
	if elapsed := now.Sub(b.updated).Seconds(); elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.perSec)
	}
	b.updated = now
	if b.tokens < 1 {
		return int(math.Ceil((1 - b.tokens) / l.perSec)), false
	}
	b.tokens--
	return 0, true
}

// sweep forgets clients whose bucket has had time to refill, so the map does
// not grow without bound.
func (l *rateLimiter) sweep(now time.Time) {
	if now.Sub(l.swept) < time.Minute {
		return
	}
	l.swept = now
	refill := time.Duration(l.burst / l.perSec * float64(time.Second))
	for key, b := range l.buckets {
		if now.Sub(b.updated) > refill {
			delete(l.buckets, key)
		}
	}
}
