package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

// getVICEProxy returns a VICEProxy instance with some default settings for testing. Some fields that aren't being used
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

type keycloakURLTest struct {
	description string
	components  []string
	expected    string
}

func TestKeycloakURL(t *testing.T) {
	tests := []keycloakURLTest{
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

func TestAllowedUsersLoadAndCheck(t *testing.T) {
	assert := assert.New(t)

	proxy := getVICEProxy()

	// Store some allowed users with the full domain suffix.
	proxy.allowedUsers.Store("alice@iplantcollaborative.org", true)
	proxy.allowedUsers.Store("bob@iplantcollaborative.org", true)

	// Full-form matches.
	assert.True(proxy.isUserAllowed("alice@iplantcollaborative.org"), "full alice should be allowed")
	assert.True(proxy.isUserAllowed("bob@iplantcollaborative.org"), "full bob should be allowed")

	// Bare username matches (Keycloak preferred_username doesn't include suffix).
	assert.True(proxy.isUserAllowed("alice"), "bare alice should match alice@iplantcollaborative.org")
	assert.True(proxy.isUserAllowed("bob"), "bare bob should match bob@iplantcollaborative.org")

	// Non-existent users.
	assert.False(proxy.isUserAllowed("eve@iplantcollaborative.org"), "eve should not be allowed")
	assert.False(proxy.isUserAllowed("eve"), "bare eve should not be allowed")
}

func TestLoadAllowedUsersFromFile(t *testing.T) {
	assert := assert.New(t)

	// Create a temp file with allowed users.
	tmpFile, err := os.CreateTemp("", "allowed-users-*")
	assert.NoError(err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	_, err = tmpFile.WriteString("alice@iplantcollaborative.org\nbob@iplantcollaborative.org\n")
	assert.NoError(err)
	_ = tmpFile.Close()

	proxy := getVICEProxy()
	count, err := proxy.loadAllowedUsers(tmpFile.Name())
	assert.NoError(err)
	assert.Equal(2, count)
	assert.True(proxy.isUserAllowed("alice@iplantcollaborative.org"))
	assert.True(proxy.isUserAllowed("bob@iplantcollaborative.org"))
	assert.False(proxy.isUserAllowed("eve@iplantcollaborative.org"))
}

func TestParseAdminEntitlements(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "core-services", []string{"core-services"}},
		{"multiple", "core-services,tito-admins,dev", []string{"core-services", "tito-admins", "dev"}},
		{"whitespace around entries", "  core-services , tito-admins  ", []string{"core-services", "tito-admins"}},
		{"empty entries dropped", "core-services,,tito-admins,", []string{"core-services", "tito-admins"}},
		{"only commas", ",,,", nil},
		{"only whitespace", "   ", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseAdminEntitlements(tt.in))
		})
	}
}

func TestAnyMatch(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want bool
	}{
		{"both empty", nil, nil, false},
		{"first empty", nil, []string{"x"}, false},
		{"second empty", []string{"x"}, nil, false},
		{"single match", []string{"x"}, []string{"x"}, true},
		{"no overlap", []string{"a", "b"}, []string{"c", "d"}, false},
		{"partial overlap", []string{"a", "b", "c"}, []string{"x", "b", "y"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, anyMatch(tt.a, tt.b))
		})
	}
}

func TestExtractStringSliceClaim(t *testing.T) {
	tests := []struct {
		name      string
		setClaim  func(tok jwt.Token)
		claimName string
		want      []string
	}{
		{
			name:      "missing claim",
			setClaim:  func(tok jwt.Token) {},
			claimName: "entitlement",
			want:      nil,
		},
		{
			name:      "string slice value",
			setClaim:  func(tok jwt.Token) { _ = tok.Set("entitlement", []string{"core-services", "dev"}) },
			claimName: "entitlement",
			want:      []string{"core-services", "dev"},
		},
		{
			name:      "interface slice value (json-decoded shape)",
			setClaim:  func(tok jwt.Token) { _ = tok.Set("entitlement", []any{"core-services", "dev"}) },
			claimName: "entitlement",
			want:      []string{"core-services", "dev"},
		},
		{
			name:      "interface slice with non-string elements skipped",
			setClaim:  func(tok jwt.Token) { _ = tok.Set("entitlement", []any{"a", 42, "b"}) },
			claimName: "entitlement",
			want:      []string{"a", "b"},
		},
		{
			name:      "wrong claim type",
			setClaim:  func(tok jwt.Token) { _ = tok.Set("entitlement", "not-a-list") },
			claimName: "entitlement",
			want:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := jwt.New()
			tt.setClaim(tok)
			assert.Equal(t, tt.want, extractStringSliceClaim(tok, tt.claimName))
		})
	}
}

func TestComputeIsAdmin(t *testing.T) {
	tests := []struct {
		name              string
		adminEntitlements []string
		setClaim          func(tok jwt.Token) // optional; nil means leave the entitlement claim unset
		want              bool
	}{
		{
			name:              "matching entitlement",
			adminEntitlements: []string{"core-services"},
			setClaim:          func(tok jwt.Token) { _ = tok.Set("entitlement", []any{"core-services"}) },
			want:              true,
		},
		{
			name:              "non-matching entitlement",
			adminEntitlements: []string{"core-services"},
			setClaim:          func(tok jwt.Token) { _ = tok.Set("entitlement", []any{"users"}) },
			want:              false,
		},
		{
			name:              "any-matching among many",
			adminEntitlements: []string{"core-services", "tito-admins"},
			setClaim:          func(tok jwt.Token) { _ = tok.Set("entitlement", []any{"users", "tito-admins"}) },
			want:              true,
		},
		{
			name:              "json-decoded interface-slice shape",
			adminEntitlements: []string{"core-services"},
			setClaim:          func(tok jwt.Token) { _ = tok.Set("entitlement", []any{"core-services"}) },
			want:              true,
		},
		{
			name:              "string-slice shape",
			adminEntitlements: []string{"core-services"},
			setClaim:          func(tok jwt.Token) { _ = tok.Set("entitlement", []string{"core-services"}) },
			want:              true,
		},
		{
			name:              "missing entitlement claim",
			adminEntitlements: []string{"core-services"},
			setClaim:          nil,
			want:              false,
		},
		{
			name:              "empty admin allowlist",
			adminEntitlements: nil,
			setClaim:          func(tok jwt.Token) { _ = tok.Set("entitlement", []any{"core-services"}) },
			want:              false,
		},
		{
			name:              "both empty",
			adminEntitlements: nil,
			setClaim:          nil,
			want:              false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := getVICEProxy()
			proxy.adminEntitlements = tt.adminEntitlements

			tok := jwt.New()
			if tt.setClaim != nil {
				tt.setClaim(tok)
			}

			assert.Equal(t, tt.want, proxy.computeIsAdmin(tok))
		})
	}
}

// requestWithSession returns an HTTP request whose cookies carry the given
// proxy-session values. Done via a save/replay round-trip on the proxy's
// CookieStore so the resulting cookie matches what the production code path
// would have written.
func requestWithSession(t *testing.T, proxy *VICEProxy, username string, isAdmin bool) *http.Request {
	t.Helper()
	rec := httptest.NewRecorder()
	src := httptest.NewRequest("GET", "http://example.com/test", nil)

	s, err := proxy.sessionStore.Get(src, sessionName)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	s.Values[sessionKey] = username
	s.Values[adminFlagKey] = isAdmin
	if err := s.Save(src, rec); err != nil {
		t.Fatalf("save session: %v", err)
	}

	dst := httptest.NewRequest("GET", "http://example.com/test", nil)
	for _, c := range rec.Result().Cookies() {
		dst.AddCookie(c)
	}
	return dst
}

func TestAuthenticateAndAuthorizeAdminBypass(t *testing.T) {
	tests := []struct {
		name      string
		username  string
		isAdmin   bool
		preStore  []string // usernames to seed into allowedUsers
		wantOK    bool
		wantUser  string
		wantErrIs error // expected sentinel for errors.Is; nil when wantOK
	}{
		{
			name:     "in allowed-users, not admin → allowed",
			username: "alice",
			isAdmin:  false,
			preStore: []string{"alice@iplantcollaborative.org"},
			wantOK:   true,
			wantUser: "alice",
		},
		{
			name:     "in allowed-users and admin → allowed",
			username: "alice",
			isAdmin:  true,
			preStore: []string{"alice@iplantcollaborative.org"},
			wantOK:   true,
			wantUser: "alice",
		},
		{
			name:     "not in allowed-users but admin → allowed (new path)",
			username: "carol",
			isAdmin:  true,
			preStore: []string{"alice@iplantcollaborative.org"},
			wantOK:   true,
			wantUser: "carol",
		},
		{
			name:      "not in allowed-users and not admin → denied",
			username:  "carol",
			isAdmin:   false,
			preStore:  []string{"alice@iplantcollaborative.org"},
			wantOK:    false,
			wantErrIs: errAccessDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := getVICEProxy()
			proxy.resourceName = "test-analysis"
			for _, u := range tt.preStore {
				proxy.allowedUsers.Store(u, true)
			}

			req := requestWithSession(t, proxy, tt.username, tt.isAdmin)
			rec := httptest.NewRecorder()

			gotUser, err := proxy.authenticateAndAuthorize(rec, req)
			if tt.wantOK {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantUser, gotUser)
			} else {
				assert.Error(t, err)
				if tt.wantErrIs != nil {
					assert.ErrorIs(t, err, tt.wantErrIs)
				}
			}
		})
	}
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
