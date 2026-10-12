// Package httpx provides the bounded HTTP behavior used by remote sources.
package httpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/clock"
)

// MaxRetryAfter is the longest server-requested delay honored.
const MaxRetryAfter = 30 * time.Second

const maxRedirects = 10

// MaxBodyBytes is the largest accepted response body.
const MaxBodyBytes int64 = 32 << 20

// ErrBodyTooLarge reports a response above MaxBodyBytes.
var ErrBodyTooLarge = errors.New("response body exceeds 32 MiB")

// Waiter gates an outbound request.
type Waiter interface{ Wait(context.Context) error }

// Sleeper is an injectable context-aware delay.
type Sleeper func(context.Context, time.Duration) error

// Client performs bounded, paced, retrying HTTP requests.
type Client struct {
	HTTP        *http.Client
	UserAgent   string
	Limiter     Waiter
	Sleep       Sleeper
	Clock       clock.Clock
	MaxAttempts int
}

// CheckRedirect refuses redirects that change scheme or host and strips Authorization.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errors.New("too many redirects")
	}
	origin := via[0].URL
	if req.URL.Scheme != origin.Scheme || req.URL.Host != origin.Host {
		return fmt.Errorf("refusing redirect to different origin %s://%s", req.URL.Scheme, req.URL.Host)
	}
	req.Header.Del("Authorization")
	return nil
}

// RetryDelay returns the clamped Retry-After delay, using the client clock for HTTP dates.
func (c *Client) RetryDelay(header http.Header) time.Duration {
	var now time.Time
	if c.Clock != nil {
		now = c.Clock.Now()
	} else {
		now = clock.System{}.Now()
	}
	return RetryAfter(header, now)
}

// New returns a client with verified TLS and explicit timeouts.
func New(version string, limiter Waiter) *Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &Client{HTTP: &http.Client{Transport: transport, Timeout: 45 * time.Second, CheckRedirect: CheckRedirect}, UserAgent: "scadenza/" + version + " (+https://github.com/HarnageaGabriel/scadenza)", Limiter: limiter, Sleep: sleep, MaxAttempts: 3}
}

// Do sends a request and returns a bounded response body.
func (c *Client) Do(ctx context.Context, request *http.Request) (int, http.Header, []byte, error) {
	attempts := c.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if c.Limiter != nil {
			if err := c.Limiter.Wait(ctx); err != nil {
				return 0, nil, nil, err
			}
		}
		req := request.Clone(ctx)
		req.Header.Set("User-Agent", c.UserAgent)
		response, err := c.HTTP.Do(req)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("send request: %w", err)
		}
		body, readErr := readBounded(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			return response.StatusCode, response.Header, nil, readErr
		}
		if closeErr != nil {
			return response.StatusCode, response.Header, nil, fmt.Errorf("close response: %w", closeErr)
		}
		if !retryable(response.StatusCode) || attempt == attempts-1 {
			return response.StatusCode, response.Header, body, nil
		}
		delay := time.Duration(1<<attempt) * 200 * time.Millisecond
		if retryAfter := c.RetryDelay(response.Header); retryAfter > 0 {
			delay = retryAfter
		}
		if err := c.Sleep(ctx, delay); err != nil {
			return 0, nil, nil, err
		}
	}
	panic("unreachable")
}

func readBounded(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(data)) > MaxBodyBytes {
		return nil, ErrBodyTooLarge
	}
	return data, nil
}

func retryable(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// IntervalLimiter spaces requests by a fixed interval.
type IntervalLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     <-chan time.Time
}

// NewIntervalLimiter returns a limiter whose first request is immediate.
func NewIntervalLimiter(interval time.Duration) *IntervalLimiter {
	ready := make(chan time.Time)
	close(ready)
	return &IntervalLimiter{interval: interval, next: ready}
}

// Wait waits until the next request slot or context cancellation.
func (l *IntervalLimiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.next:
		l.next = time.After(l.interval)
		return nil
	}
}

// RetryAfter parses a delta-seconds or HTTP-date Retry-After value, clamped to MaxRetryAfter.
func RetryAfter(header http.Header, now time.Time) time.Duration {
	value := strings.TrimSpace(header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	var delay time.Duration
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return 0
		}
		if seconds > int64(MaxRetryAfter/time.Second) {
			return MaxRetryAfter
		}
		delay = time.Duration(seconds) * time.Second
	} else if when, err := http.ParseTime(value); err == nil {
		delay = when.Sub(now)
	} else {
		return 0
	}
	if delay < 0 {
		return 0
	}
	if delay > MaxRetryAfter {
		return MaxRetryAfter
	}
	return delay
}
