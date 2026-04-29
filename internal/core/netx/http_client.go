package netx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

type RateLimiter struct {
	ticker *time.Ticker
	ch     <-chan time.Time
}

func NewRateLimiter(requestPerSecond float64) *RateLimiter {
	if requestPerSecond <= 0 {
		requestPerSecond = 1
	}
	interval := time.Duration(float64(time.Second) / requestPerSecond)
	ticker := time.NewTicker(interval)
	return &RateLimiter{ticker: ticker, ch: ticker.C}
}

func (r *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.ch:
		return nil
	}
}

func (r *RateLimiter) Stop() {
	r.ticker.Stop()
}

func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
	}
}

func DoRequestWithRetry(
	ctx context.Context,
	client *http.Client,
	req *http.Request,
	retry int,
) ([]byte, error) {
	if retry < 0 {
		retry = 0
	}
	var lastErr error
	for i := 0; i <= retry; i++ {
		cloned := req.Clone(ctx)
		resp, err := client.Do(cloned)
		if err != nil {
			lastErr = err
		} else {
			body, readErr := io.ReadAll(resp.Body)
			closeErr := resp.Body.Close()
			if readErr != nil {
				lastErr = readErr
			} else if closeErr != nil {
				lastErr = closeErr
			} else if resp.StatusCode >= 400 {
				lastErr = fmt.Errorf("http status: %d", resp.StatusCode)
			} else {
				return body, nil
			}
		}

		if i < retry {
			backoff := time.Duration(i+1) * 300 * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	return nil, lastErr
}
