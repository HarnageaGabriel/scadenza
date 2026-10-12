package httpx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientRetriesAndSetsUserAgent(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts++
		if request.Header.Get("User-Agent") != "test-agent" {
			t.Error("missing user agent")
		}
		if attempts < 3 {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()
	client := &Client{HTTP: server.Client(), UserAgent: "test-agent", MaxAttempts: 3, Sleep: func(context.Context, time.Duration) error { return nil }}
	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	status, _, body, err := client.Do(context.Background(), request)
	if err != nil || status != http.StatusOK || string(body) != "ok" || attempts != 3 {
		t.Fatalf("Do() = %d, %q, %v (%d attempts)", status, body, err, attempts)
	}
}

func TestClientErrors(t *testing.T) {
	client := &Client{HTTP: &http.Client{Transport: roundTripper(func(*http.Request) (*http.Response, error) { return nil, errors.New("boom") })}, MaxAttempts: 1}
	request, _ := http.NewRequest(http.MethodGet, "https://example.invalid", nil)
	if _, _, _, err := client.Do(context.Background(), request); err == nil {
		t.Fatal("expected transport error")
	}
	client.HTTP.Transport = roundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(io.LimitReader(zeroReader{}, MaxBodyBytes+1))}, nil
	})
	if _, _, _, err := client.Do(context.Background(), request); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("error = %v", err)
	}
}

func TestHelpers(t *testing.T) {
	header := http.Header{"Retry-After": {"12"}}
	if got := RetryAfter(header); got != 12*time.Second {
		t.Fatalf("RetryAfter = %v", got)
	}
	if RetryAfter(http.Header{"Retry-After": {"date"}}) != 0 || !retryable(503) || retryable(400) {
		t.Fatal("helper result mismatch")
	}
	limiter := NewIntervalLimiter(time.Hour)
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait error = %v", err)
	}
	_ = New("v1", nil)
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := sleep(ctx2, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("sleep error = %v", err)
	}
}

func TestRetrySleepCancellationAndSingleResponse(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "https://example.invalid", nil)
	client := &Client{HTTP: &http.Client{Transport: roundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString("retry"))}, nil
	})}, MaxAttempts: 2, Sleep: func(context.Context, time.Duration) error { return context.Canceled }}
	if _, _, _, err := client.Do(context.Background(), request); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	client = &Client{HTTP: &http.Client{Transport: roundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 400, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString("bad"))}, nil
	})}, MaxAttempts: 0}
	status, _, body, err := client.Do(context.Background(), request)
	if err != nil || status != 400 || string(body) != "bad" {
		t.Fatalf("Do = %d %q %v", status, body, err)
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (r roundTripper) RoundTrip(request *http.Request) (*http.Response, error) { return r(request) }

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 0
	}
	return len(buffer), nil
}
