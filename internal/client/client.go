package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"time"
)

// QratorClient is a client for interacting with the Qrator API.
// It manages HTTP requests with authentication, debug logging, and retry logic.
type QratorClient struct {
	apiKey     string        // API key for authenticating requests
	endpoint   string        // Base URL of the Qrator API
	client     *http.Client  // HTTP client for making requests
	debug      bool          // Flag to enable/disable debug logging
	idCounter  uint64        // Atomic counter for generating unique request IDs
	maxRetries int           // Maximum number of retry attempts
	retryDelay time.Duration // Base delay between retries
}

// APIRequest represents a JSON-RPC request to the Qrator API.
type APIRequest struct {
	Method string      `json:"method"`
	Params interface{} `json:"params"`
	ID     uint64      `json:"id"`
}

// APIResponse represents a JSON-RPC response from the Qrator API.
type APIResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *string         `json:"error"`
	ID     uint64          `json:"id"`
}

// NewQratorClient creates a new QratorClient instance with the specified configuration.
//
// Parameters:
//   - apiKey: The API key for authenticating requests to the Qrator API.
//   - endpoint: The base URL of the Qrator API (e.g., "https://api.qrator.net").
//   - debug: Enables debug logging of requests and responses.
//
// Returns:
//   - A pointer to a QratorClient instance.
//   - An error if the provided endpoint is invalid.
func NewQratorClient(apiKey, endpoint string, debug bool) *QratorClient {
	// Validate API key
	if apiKey == "" {
		log.Printf("[WARN] apiKey is empty")
	}

	// Validate endpoint
	if endpoint == "" {
		log.Printf("[WARN] endpoint is empty")
	} else {
		endpoint = strings.TrimSuffix(endpoint, "/")
	}

	// Configure HTTP client with timeouts and connection pooling
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   10,
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	return &QratorClient{
		apiKey:     apiKey,
		endpoint:   endpoint,
		client:     client,
		debug:      debug,
		idCounter:  0,
		maxRetries: 3,
		retryDelay: 1 * time.Second,
	}
}

// MakeRequest sends a JSON-RPC request to the Qrator API with retry logic and returns the result.
//
// Parameters:
//   - ctx: The context for controlling request cancellation and timeouts.
//   - path: The API endpoint path (e.g., "/v1/domain").
//   - method: The JSON-RPC method name (e.g., "getDomain").
//   - params: The parameters for the JSON-RPC request.
//
// Returns:
//   - The raw JSON result from the API response.
//   - An error if the request fails, the response status is not OK, or the API returns an error.
func (c *QratorClient) MakeRequest(ctx context.Context, path string, method string, params interface{}) (json.RawMessage, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff with jitter
			delay := time.Duration(float64(c.retryDelay) * math.Pow(2, float64(attempt-1)))
			if c.debug {
				log.Printf("[DEBUG] Retrying request (attempt %d/%d) after %v", attempt, c.maxRetries, delay)
			}

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		result, err := c.makeRequestAttempt(ctx, path, method, params)
		if err == nil {
			return result, nil
		}

		lastErr = err

		// Check if the request should be retried
		if !c.shouldRetry(err) {
			break
		}

		if c.debug {
			log.Printf("[DEBUG] Request failed (attempt %d/%d): %v", attempt+1, c.maxRetries+1, err)
		}
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", c.maxRetries+1, lastErr)
}

// makeRequestAttempt performs a single request without retry logic
func (c *QratorClient) makeRequestAttempt(ctx context.Context, path string, method string, params interface{}) (json.RawMessage, error) {
	url := fmt.Sprintf("%s%s", c.endpoint, path)

	// Log request details if debug is enabled
	if c.debug {
		log.Printf("[DEBUG] Preparing request to %s", url)
		log.Printf("[DEBUG] Method: %s", method)

		paramsJSON, err := json.MarshalIndent(params, "", "  ")
		if err == nil {
			safeParams := c.maskSensitiveData(string(paramsJSON))
			log.Printf("[DEBUG] Params: %s", safeParams)
		}
	}

	// Generate unique request ID
	requestID := atomic.AddUint64(&c.idCounter, 1)

	// Create JSON-RPC request
	requestBody := APIRequest{
		Method: method,
		Params: params,
		ID:     requestID,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body: %w", err)
	}

	// Log request body if debug is enabled
	if c.debug {
		safeBody := c.maskSensitiveData(string(jsonBody))
		log.Printf("[DEBUG] Request body: %s", safeBody)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Qrator-Auth", c.apiKey)

	// Log full HTTP request if debug is enabled
	if c.debug {
		dump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			log.Printf("[DEBUG] HTTP Request:\n%s", c.maskSensitiveData(string(dump)))
		}
	}

	// Execute HTTP request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making HTTP request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("[ERROR] Failed to close response body: %v", err)
		}
	}()

	// Log HTTP response if debug is enabled
	if c.debug {
		dump, err := httputil.DumpResponse(resp, true)
		if err == nil {
			log.Printf("[DEBUG] HTTP Response:\n%s", c.maskSensitiveData(string(dump)))
		}
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	// Log raw response body if debug is enabled
	if c.debug {
		log.Printf("[DEBUG] Raw response body: %s", c.maskSensitiveData(string(body)))
	}

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, c.maskSensitiveData(string(body)))
	}

	// Parse JSON-RPC response
	var apiResponse APIResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w, body: %s", err, c.maskSensitiveData(string(body)))
	}

	// Check for API-level errors
	if apiResponse.Error != nil {
		details := resp.Header.Get("X-Qrator-API-Error-Details")
		if c.debug {
			log.Printf("[ERROR] API error response: %s (details: %s)", *apiResponse.Error, details)
		}
		if details != "" {
			return nil, fmt.Errorf("API error: %s (%s)", *apiResponse.Error, details)
		}
		return nil, fmt.Errorf("API error: %s", *apiResponse.Error)
	}

	return apiResponse.Result, nil
}

// maskSensitiveData masks sensitive data (e.g., API keys) in log outputs.
//
// Parameters:
//   - input: The string to process for sensitive data.
//
// Returns:
//   - The input string with sensitive data replaced by "[REDACTED]".
func (c *QratorClient) maskSensitiveData(input string) string {
	// Mask API key in headers or body
	if c.apiKey != "" {
		input = strings.ReplaceAll(input, c.apiKey, "[REDACTED]")
	}
	// Add additional masking logic for other sensitive data (e.g., certificates, tokens)
	// Example:
	// if strings.Contains(input, "PRIVATE KEY") {
	//     input = strings.ReplaceAll(input, input, "[REDACTED: PRIVATE KEY]")
	// }
	return input
}

// shouldRetry determines whether the request should be retried for the given error
func (c *QratorClient) shouldRetry(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Do not retry on API errors (typically 4xx codes)
	if strings.Contains(errStr, "API error:") {
		return false
	}

	// Conditions for retry
	retryConditions := []string{
		"connection refused",
		"timeout",
		"temporary failure",
		"network",
		"status code: 5",   // 5xx errors
		"status code: 429", // too many requests
	}

	for _, condition := range retryConditions {
		if strings.Contains(errStr, condition) {
			return true
		}
	}

	return false
}
