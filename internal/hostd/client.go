// Package hostd is a small client for the hostd.cloud public API
// (https://api.hostd.cloud/v1). Endpoints follow the official Terraform
// provider (hostdcloud/terraform-provider-hostd, internal/client).
package hostd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the public API root including the version prefix.
const DefaultBaseURL = "https://api.hostd.cloud/v1"

// Client talks to one hostd project. It never logs or returns the token.
type Client struct {
	BaseURL   string
	Project   string
	token     string
	UserAgent string
	HTTP      *http.Client
	// RetryBudget bounds 429/5xx retries of a single call.
	RetryBudget time.Duration
	// Sleep is replaceable in tests.
	Sleep func(context.Context, time.Duration) error
}

// New returns a client for one project.
func New(baseURL, project, token string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"), Project: project, token: token,
		UserAgent: "kandev-provider-hostd/0.0.0-spike", HTTP: &http.Client{Timeout: 3 * time.Minute},
		RetryBudget: 2 * time.Minute, Sleep: sleepCtx,
	}
}

// Error is a non-2xx API answer. Body is the API's JSON error text; it never
// contains the request token.
type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("hostd API returned %d: %s", e.Status, truncate(e.Body, 300))
}

// IsNotFound reports a 404.
func IsNotFound(err error) bool {
	var apiErr *Error
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound
}

// IsNoFreeIPv4 reports the transient "No free public IPv4 addresses" create
// failure seen live on a parallel create (2026-11-26).
func IsNoFreeIPv4(err error) bool {
	var apiErr *Error
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusBadRequest &&
		strings.Contains(apiErr.Body, "No free public IPv4")
}

// IsQuota reports account/project quota errors that a retry will not fix.
func IsQuota(err error) bool {
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		return false
	}
	for _, phrase := range []string{"Account CPU limit reached", "Max cores per VM", "Project RAM limit reached", "Project storage limit reached", "project limit for this cluster"} {
		if strings.Contains(apiErr.Body, phrase) {
			return true
		}
	}
	return false
}

// IsInterrupted reports a transport failure where the request may or may not
// have reached the API (timeout, reset, cancel).
func IsInterrupted(err error) bool {
	var apiErr *Error
	if err == nil || errors.As(err, &apiErr) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(c.RetryBudget)
	for attempt := 0; ; attempt++ {
		resp, data, err := c.send(ctx, method, path, payload)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Only idempotent reads are retried after a transport error.
			if method == http.MethodGet && attempt < 8 && time.Now().Before(deadline) {
				if err := c.Sleep(ctx, backoff(attempt)); err != nil {
					return err
				}
				continue
			}
			return err
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt < 10 {
			wait := retryAfter(resp.Header.Get("Retry-After"), attempt)
			if time.Now().Add(wait).Before(deadline) {
				if err := c.Sleep(ctx, wait); err != nil {
					return err
				}
				continue
			}
		}
		if method == http.MethodGet && resp.StatusCode >= 500 && attempt < 8 && time.Now().Before(deadline) {
			if err := c.Sleep(ctx, backoff(attempt)); err != nil {
				return err
			}
			continue
		}
		if resp.StatusCode >= 300 {
			return &Error{Status: resp.StatusCode, Body: strings.TrimSpace(string(data))}
		}
		if out != nil && len(bytes.TrimSpace(data)) > 0 {
			return json.Unmarshal(data, out)
		}
		return nil
	}
}

func (c *Client) send(ctx context.Context, method, path string, payload []byte) (*http.Response, []byte, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp, data, err
}

func retryAfter(header string, attempt int) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(header)); err == nil && seconds >= 0 {
		d := time.Duration(seconds) * time.Second
		return d + jitter(d)
	}
	if when, err := http.ParseTime(header); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
		return 0
	}
	return backoff(attempt)
}

func backoff(attempt int) time.Duration {
	if attempt > 6 {
		attempt = 6
	}
	d := 200 * time.Millisecond << attempt
	if d > 10*time.Second {
		d = 10 * time.Second
	}
	return d + jitter(d)
}

func jitter(d time.Duration) time.Duration {
	span := d / 5
	if span > 250*time.Millisecond {
		span = 250 * time.Millisecond
	}
	if span < time.Millisecond {
		return 0
	}
	return time.Duration(rand.Int64N(int64(span)))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
