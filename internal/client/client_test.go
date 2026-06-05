package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *QratorClient) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, NewQratorClient("test-api-key", srv.URL, false)
}

func TestMakeRequest_Success(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var req APIRequest
		json.NewDecoder(r.Body).Decode(&req)

		resp := APIResponse{
			Result: json.RawMessage(`"ok"`),
			ID:     req.ID,
		}
		json.NewEncoder(w).Encode(resp)
	})

	result, err := c.MakeRequest(context.Background(), "/test", "test_method", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var s string
	json.Unmarshal(result, &s)
	if s != "ok" {
		t.Errorf("result = %q, want ok", s)
	}
}

func TestMakeRequest_APIError(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var req APIRequest
		json.NewDecoder(r.Body).Decode(&req)

		errMsg := "bad request"
		resp := APIResponse{
			Error: &errMsg,
			ID:    req.ID,
		}
		json.NewEncoder(w).Encode(resp)
	})

	_, err := c.MakeRequest(context.Background(), "/test", "test_method", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "API error") {
		t.Errorf("error = %q, should contain 'API error'", err.Error())
	}
}

func TestMakeRequest_APIErrorWithDetails(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var req APIRequest
		json.NewDecoder(r.Body).Decode(&req)

		errMsg := "validation failed"
		w.Header().Set("X-Qrator-API-Error-Details", "field 'name' is required")
		resp := APIResponse{
			Error: &errMsg,
			ID:    req.ID,
		}
		json.NewEncoder(w).Encode(resp)
	})

	_, err := c.MakeRequest(context.Background(), "/test", "test_method", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "field 'name' is required") {
		t.Errorf("error = %q, should contain details", err.Error())
	}
}

func TestMakeRequest_HTTP500ReturnsError(t *testing.T) {
	attempts := 0
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	})

	_, err := c.MakeRequest(context.Background(), "/test", "test_method", nil)
	if err == nil {
		t.Fatal("expected error on HTTP 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, should contain '500'", err.Error())
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (no retries)", attempts)
	}
}

func TestMakeRequest_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var req APIRequest
		json.NewDecoder(r.Body).Decode(&req)
		resp := APIResponse{Result: json.RawMessage(`"ok"`), ID: req.ID}
		json.NewEncoder(w).Encode(resp)
	})

	_, err := c.MakeRequest(ctx, "/test", "test_method", nil)
	if err == nil {
		t.Fatal("expected error due to context cancellation")
	}
}

func TestMakeRequest_AuthHeader(t *testing.T) {
	var gotHeader string
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Qrator-Auth")
		var req APIRequest
		json.NewDecoder(r.Body).Decode(&req)
		resp := APIResponse{Result: json.RawMessage(`"ok"`), ID: req.ID}
		json.NewEncoder(w).Encode(resp)
	})

	c.MakeRequest(context.Background(), "/test", "test_method", nil)

	if gotHeader != "test-api-key" {
		t.Errorf("X-Qrator-Auth = %q, want test-api-key", gotHeader)
	}
}

func TestMakeRequest_RequestIDIncrement(t *testing.T) {
	var ids []uint64
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var req APIRequest
		json.NewDecoder(r.Body).Decode(&req)
		ids = append(ids, req.ID)
		resp := APIResponse{Result: json.RawMessage(`"ok"`), ID: req.ID}
		json.NewEncoder(w).Encode(resp)
	})

	for i := 0; i < 3; i++ {
		c.MakeRequest(context.Background(), "/test", "method", nil)
	}

	if len(ids) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(ids))
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Errorf("request ID should increment: ids[%d]=%d <= ids[%d]=%d", i, ids[i], i-1, ids[i-1])
		}
	}
}

func TestMakeRequest_MethodAndParams(t *testing.T) {
	var gotMethod string
	var gotParams json.RawMessage
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var req APIRequest
		json.NewDecoder(r.Body).Decode(&req)
		gotMethod = req.Method
		gotParams, _ = json.Marshal(req.Params)
		resp := APIResponse{Result: json.RawMessage(`"ok"`), ID: req.ID}
		json.NewEncoder(w).Encode(resp)
	})

	c.MakeRequest(context.Background(), "/request/domain/123", "services_get", nil)

	if gotMethod != "services_get" {
		t.Errorf("method = %q, want services_get", gotMethod)
	}
	if string(gotParams) != "null" {
		t.Errorf("params = %s, want null", string(gotParams))
	}
}

// ---------------------------------------------------------------------------
// maskSensitiveData
// ---------------------------------------------------------------------------

func TestMaskSensitiveData(t *testing.T) {
	c := &QratorClient{apiKey: "secret-key-123"}

	t.Run("masks api key", func(t *testing.T) {
		input := "Authorization: secret-key-123"
		got := c.maskSensitiveData(input)
		if strings.Contains(got, "secret-key-123") {
			t.Errorf("API key should be masked, got: %q", got)
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("should contain [REDACTED], got: %q", got)
		}
	})

	t.Run("empty api key no-op", func(t *testing.T) {
		c2 := &QratorClient{apiKey: ""}
		input := "some text"
		got := c2.maskSensitiveData(input)
		if got != input {
			t.Errorf("empty key should not modify input, got: %q", got)
		}
	})

	t.Run("no key in input unchanged", func(t *testing.T) {
		input := "no sensitive data here"
		got := c.maskSensitiveData(input)
		if got != input {
			t.Errorf("input without key should be unchanged, got: %q", got)
		}
	})
}
