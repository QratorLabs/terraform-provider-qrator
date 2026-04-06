package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// mockCall records a single MakeRequest invocation.
type mockCall struct {
	Path   string
	Method string
	Params interface{}
}

// mockClient implements client.QratorClientAPI for use in unit tests.
// Responses are keyed by "path:method". Errors take precedence over responses.
type mockClient struct {
	mu        sync.Mutex
	responses map[string]json.RawMessage
	errors    map[string]error
	calls     []mockCall
}

func newMockClient() *mockClient {
	return &mockClient{
		responses: make(map[string]json.RawMessage),
		errors:    make(map[string]error),
	}
}

func (m *mockClient) key(path, method string) string {
	return path + ":" + method
}

// On registers a JSON-serialisable response for the given path+method.
func (m *mockClient) On(path, method string, response interface{}) *mockClient {
	b, err := json.Marshal(response)
	if err != nil {
		panic(fmt.Sprintf("mockClient.On: cannot marshal response: %v", err))
	}
	m.responses[m.key(path, method)] = json.RawMessage(b)
	return m
}

// OnRaw registers a raw JSON response for the given path+method.
func (m *mockClient) OnRaw(path, method string, raw json.RawMessage) *mockClient {
	m.responses[m.key(path, method)] = raw
	return m
}

// OnError registers an error response for the given path+method.
func (m *mockClient) OnError(path, method string, err error) *mockClient {
	m.errors[m.key(path, method)] = err
	return m
}

func (m *mockClient) MakeRequest(_ context.Context, path, method string, params interface{}) (json.RawMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockCall{Path: path, Method: method, Params: params})
	k := m.key(path, method)
	if err, ok := m.errors[k]; ok {
		return nil, err
	}
	if raw, ok := m.responses[k]; ok {
		return raw, nil
	}
	return nil, fmt.Errorf("mockClient: no response registered for %s", k)
}

// Called returns all recorded calls.
func (m *mockClient) Called() []mockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mockCall(nil), m.calls...)
}

// CallsFor returns calls matching the given path and method.
func (m *mockClient) CallsFor(path, method string) []mockCall {
	var out []mockCall
	for _, c := range m.Called() {
		if c.Path == path && c.Method == method {
			out = append(out, c)
		}
	}
	return out
}
