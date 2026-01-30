package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

// getVICEProxy returns a VICEProxy instance with some default settnigs for testing. Some fields that aren't being used
// during testing are omitted.
func getVICEProxy() *VICEProxy {
	// Create a session store for testing
	authkey := make([]byte, 64)
	_, _ = rand.Read(authkey)
	sessionStore := sessions.NewCookieStore(authkey)

	return &VICEProxy{
		keycloakBaseURL:      "https://keycloak.example.org",
		keycloakRealm:        "example",
		keycloakClientID:     "example-client",
		keycloakClientSecret: "example-secret",
		frontendURL:          "https://foobarbaz.example.run",
		backendURL:           "http://localhost:8888",
		wsbackendURL:         "http://localhost:8888",
		sessionStore:         sessionStore,
		disableAuth:          false,
	}
}

type KeycloakURLTest struct {
	description string
	components  []string
	expected    string
}

func TestKeycloakURL(t *testing.T) {
	tests := []KeycloakURLTest{
		{
			description: "no additional components",
			components:  []string{},
			expected:    "https://keycloak.example.org/realms/example/protocol/openid-connect",
		},
		{
			description: "one additional component",
			components:  []string{"foo"},
			expected:    "https://keycloak.example.org/realms/example/protocol/openid-connect/foo",
		},
		{
			description: "multiple additional components",
			components:  []string{"foo", "bar", "baz"},
			expected:    "https://keycloak.example.org/realms/example/protocol/openid-connect/foo/bar/baz",
		},
		{
			description: "components that require encoding",
			components:  []string{"foo bar"},
			expected:    "https://keycloak.example.org/realms/example/protocol/openid-connect/foo%20bar",
		},
	}

	// Run the tests.
	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			assert := assert.New(t)
			proxy := getVICEProxy()

			// Build the actual URL.
			actualURL, err := proxy.KeycloakURL(test.components...)
			assert.NoError(err, "keycloakURL should not return an error")
			assert.Equal(test.expected, actualURL.String(), "the actual URL should equal the expected URL")
		})
	}
}

func TestProxyWithAuthDisabled(t *testing.T) {
	assert := assert.New(t)

	// Create a test backend server
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	// Create proxy with auth disabled
	proxy := getVICEProxy()
	proxy.disableAuth = true
	proxy.backendURL = backend.URL

	// Get the proxy handler
	proxyHandler, err := proxy.Proxy()
	assert.NoError(err, "creating proxy handler should not error")

	// Create a test request without authentication
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	// Execute the request
	proxyHandler.ServeHTTP(w, req)

	// Verify the backend was called and request succeeded
	assert.True(backendCalled, "backend should have been called")
	assert.Equal(http.StatusOK, w.Code, "request should succeed without authentication")
}

func TestProxyWithAuthEnabled(t *testing.T) {
	assert := assert.New(t)

	// Create a test backend server
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	// Create proxy with auth enabled (default)
	proxy := getVICEProxy()
	proxy.disableAuth = false
	proxy.backendURL = backend.URL

	// Get the proxy handler
	proxyHandler, err := proxy.Proxy()
	assert.NoError(err, "creating proxy handler should not error")

	// Create a test request without authentication
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	// Execute the request
	proxyHandler.ServeHTTP(w, req)

	// Verify the backend was NOT called and request was rejected
	assert.False(backendCalled, "backend should not have been called without authentication")
	assert.Equal(http.StatusForbidden, w.Code, "request should be rejected without authentication")
}

func TestAuthenticateAndAuthorizeWithoutSession(t *testing.T) {
	assert := assert.New(t)

	proxy := getVICEProxy()
	proxy.resourceName = "test-resource"

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	// Attempt authentication without a valid session
	username, err := proxy.authenticateAndAuthorize(w, req)

	// Should fail with empty username and error
	assert.Empty(username, "username should be empty without a valid session")
	assert.Error(err, "should return an error without a valid session")
}

func TestDisableAuthFlag(t *testing.T) {
	assert := assert.New(t)

	// Test that disableAuth field defaults to false
	proxy := getVICEProxy()
	assert.False(proxy.disableAuth, "disableAuth should default to false")

	// Test that disableAuth can be set to true
	proxy.disableAuth = true
	assert.True(proxy.disableAuth, "disableAuth should be settable to true")
}

func TestCheckKeycloakAuthorizationGranted(t *testing.T) {
	assert := assert.New(t)

	// Mock Keycloak token endpoint that grants the UMA ticket.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(http.MethodPost, r.Method)
		assert.Equal("Bearer fake-access-token", r.Header.Get("Authorization"))

		err := r.ParseForm()
		assert.NoError(err)
		assert.Equal("urn:ietf:params:oauth:grant-type:uma-ticket", r.FormValue("grant_type"))
		assert.Equal("example-client", r.FormValue("audience"))
		assert.Equal("test-analysis-uuid#access", r.FormValue("permission"))

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"rpt-token"}`))
	}))
	defer server.Close()

	proxy := getVICEProxy()
	proxy.keycloakBaseURL = server.URL
	proxy.resourceName = "test-analysis-uuid"
	proxy.ssoClient = http.Client{Timeout: 5 * time.Second}

	err := proxy.CheckKeycloakAuthorization("fake-access-token")
	assert.NoError(err, "authorization should succeed when Keycloak grants the UMA ticket")
}

func TestCheckKeycloakAuthorizationDenied(t *testing.T) {
	assert := assert.New(t)

	// Mock Keycloak token endpoint that denies the UMA ticket.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"access_denied","error_description":"not_authorized"}`))
	}))
	defer server.Close()

	proxy := getVICEProxy()
	proxy.keycloakBaseURL = server.URL
	proxy.resourceName = "test-analysis-uuid"
	proxy.ssoClient = http.Client{Timeout: 5 * time.Second}

	err := proxy.CheckKeycloakAuthorization("fake-access-token")
	assert.Error(err, "authorization should fail when Keycloak denies the UMA ticket")
	assert.Contains(err.Error(), "denied access")
}

// generateTestJWKS creates a JWKS JSON response containing an RSA public key.
func generateTestJWKS(t *testing.T) []byte {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	key, err := jwk.New(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create JWK: %v", err)
	}
	_ = key.Set(jwk.KeyIDKey, "test-key-id")
	_ = key.Set(jwk.AlgorithmKey, "RS256")
	_ = key.Set(jwk.KeyUsageKey, "sig")

	set := jwk.NewSet()
	set.Add(key)

	data, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("failed to marshal JWK set: %v", err)
	}
	return data
}

func TestFetchKeycloakCertsWithoutCache(t *testing.T) {
	assert := assert.New(t)

	jwksData := generateTestJWKS(t)

	var fetchCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetchCount, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksData)
	}))
	defer server.Close()

	proxy := getVICEProxy()
	proxy.keycloakBaseURL = server.URL
	proxy.ssoClient = http.Client{Timeout: 5 * time.Second}
	// jwksAutoRefresh is nil, so caching is disabled.

	// Two calls should both hit the server.
	keySet1, err := proxy.FetchKeycloakCerts()
	assert.NoError(err)
	assert.NotNil(keySet1)

	keySet2, err := proxy.FetchKeycloakCerts()
	assert.NoError(err)
	assert.NotNil(keySet2)

	assert.Equal(int32(2), atomic.LoadInt32(&fetchCount),
		"without caching, each call should fetch from the server")
}

func TestFetchKeycloakCertsWithCache(t *testing.T) {
	assert := assert.New(t)

	jwksData := generateTestJWKS(t)

	var fetchCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetchCount, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksData)
	}))
	defer server.Close()

	proxy := getVICEProxy()
	proxy.keycloakBaseURL = server.URL

	// Build the certs URL and set up the cache.
	certsURL, err := proxy.KeycloakURL("certs")
	assert.NoError(err)
	proxy.jwksCertsURL = certsURL.String()

	ar := jwk.NewAutoRefresh(context.Background())
	ar.Configure(proxy.jwksCertsURL, jwk.WithMinRefreshInterval(1*time.Hour))
	proxy.jwksAutoRefresh = ar

	// First call fetches from the server.
	keySet1, err := proxy.FetchKeycloakCerts()
	assert.NoError(err)
	assert.NotNil(keySet1)

	// Second call should use the cache.
	keySet2, err := proxy.FetchKeycloakCerts()
	assert.NoError(err)
	assert.NotNil(keySet2)

	// Third call should also use the cache.
	keySet3, err := proxy.FetchKeycloakCerts()
	assert.NoError(err)
	assert.NotNil(keySet3)

	assert.Equal(int32(1), atomic.LoadInt32(&fetchCount),
		"with caching, only the first call should fetch from the server")
}
