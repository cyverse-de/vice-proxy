package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithFields(logrus.Fields{
	"service": "vice-proxy",
	"art-id":  "vice-proxy",
	"group":   "org.cyverse",
})

const (
	stateSessionName = "state-session"
	stateSessionKey  = "state-session-key"
	sessionName      = "proxy-session"
	sessionKey       = "proxy-session-key"
	keycloakSidKey   = "keycloak-sid"

	// permissionsFilePath is the path to the ConfigMap-mounted allowed-users file.
	permissionsFilePath = "/etc/vice-permissions/allowed-users"
)

// VICEProxy contains the application logic that handles Keycloak OIDC
// authentication, session management, ConfigMap-based authorization, and
// request proxying.
type VICEProxy struct {
	keycloakBaseURL      string                // The URL to use when checking for Keycloak authentication.
	keycloakRealm        string                // The realm to use when checking for Keycloak authentication.
	keycloakClientID     string                // The OIDC client ID for Keycloak.
	keycloakClientSecret string                // The OIDC client secret for Keycloak.
	frontendURL          string                // The redirect URL.
	backendURL           string                // The backend URL to forward to.
	wsbackendURL         string                // The websocket URL to forward requests to.
	resourceName         string                // The UUID of the analysis.
	sessionStore         *sessions.CookieStore // The backend session storage.
	ssoClient            http.Client           // The HTTP client for back-channel requests to the IDP.
	disableAuth          bool                  // If true, authentication and authorization are disabled.
	jwksAutoRefresh      *jwk.AutoRefresh      // Cached JWKS fetcher, nil if caching is disabled.
	jwksCertsURL         string                // The resolved JWKS certs URL, set during initialization.
	activeSessions       sync.Map              // Tracks valid Keycloak session IDs for back-channel logout.
	allowedUsers         sync.Map              // In-memory set of usernames allowed to access this analysis.
}

// loadAllowedUsers reads the allowed-users file and populates the in-memory set.
// Returns the number of users loaded, or an error if the file cannot be read.
func (c *VICEProxy) loadAllowedUsers(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening permissions file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// Read all users from the file before touching the live map.
	newUsers := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			newUsers[line] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("reading permissions file %s: %w", path, err)
	}

	// Swap in the new set: clear old entries, then store new ones.
	// Note: there is a brief window between the Range+Delete and Store passes
	// during which the map is empty. This is acceptable because the worst case
	// is a single request getting a spurious 403 while the reload races; the
	// file-watch goroutine is the only writer so the window is very short.
	c.allowedUsers.Range(func(key, _ any) bool {
		c.allowedUsers.Delete(key)
		return true
	})
	for user := range newUsers {
		c.allowedUsers.Store(user, true)
	}

	return len(newUsers), nil
}

// isUserAllowed checks whether a username is in the allowed-users set.
func (c *VICEProxy) isUserAllowed(username string) bool {
	_, ok := c.allowedUsers.Load(username)
	return ok
}

// watchPermissionsFile watches the permissions directory for ConfigMap volume
// updates (K8s performs a symlink swap) and reloads the allowed-users set.
// Returns an error if the watcher cannot be created; the caller should treat
// this as fatal since the proxy will never pick up permission changes.
func (c *VICEProxy) watchPermissionsFile(path string) error {
	dir := filepath.Dir(path)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating fsnotify watcher for %s: %w", dir, err)
	}

	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return fmt.Errorf("adding watch on %s: %w", dir, err)
	}

	log.Infof("watching %s for permission updates", dir)

	go func() {
		defer func() { _ = watcher.Close() }()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// K8s ConfigMap volumes update via symlink swap, which
				// generates Create events on the ..data symlink.
				if event.Op&(fsnotify.Create|fsnotify.Write) != 0 {
					count, err := c.loadAllowedUsers(path)
					if err != nil {
						log.Errorf("failed to reload permissions: %v", err)
					} else {
						log.Infof("reloaded permissions: %d allowed users", count)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Errorf("fsnotify error: %v", err)
			}
		}
	}()

	return nil
}

// KeycloakURL generates a URL for a Keycloak OpenID Connect endpoint. Optional
// path components are appended after the base OpenID Connect path.
func (c *VICEProxy) KeycloakURL(components ...string) (*url.URL, error) {
	keycloakURL, err := url.Parse(c.keycloakBaseURL)
	if err != nil {
		return nil, err
	}

	// Build the fixed OpenID Connect path prefix, then append any caller-supplied
	// components. JoinPath handles percent-encoding and slash normalization.
	parts := append([]string{"realms", c.keycloakRealm, "protocol", "openid-connect"}, components...)
	return keycloakURL.JoinPath(parts...), nil
}

// TokenResponse represents the response to an OpenID Connect token endpoint.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}

// FetchKeycloakCerts calls Keycloak's certificate endpoint to get the set of signing certificates, and returns
// the parsed certificate set. If JWKS caching is enabled, returns the cached key set.
func (c *VICEProxy) FetchKeycloakCerts() (jwk.Set, error) {
	if c.jwksAutoRefresh != nil {
		return c.jwksAutoRefresh.Fetch(context.Background(), c.jwksCertsURL)
	}

	url, err := c.KeycloakURL("certs")
	if err != nil {
		return nil, err
	}

	resp, err := c.ssoClient.Get(url.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return jwk.Parse(body)
}

// ValidateKeycloakToken verifies the signature of a Keycloak token and returns a parsed version of it.
func (c *VICEProxy) ValidateKeycloakToken(encodedToken string) (jwt.Token, error) {
	keySet, err := c.FetchKeycloakCerts()
	if err != nil {
		return nil, err
	}

	return jwt.Parse([]byte(encodedToken), jwt.WithKeySet(keySet))
}

// HandleAuthorizationCode accepts an authorization code in the query string and uses it to obtain an access token.
func (c *VICEProxy) HandleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	log.Debug("validating an authorization code received from Keycloak")
	var err error

	// Validate the state query parameter to mitigate CSRF attacks.
	actualState := r.URL.Query().Get("state")
	if actualState == "" {
		err = errors.New("no state found in query string")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session, err := c.sessionStore.Get(r, stateSessionName)
	if err != nil {
		err = errors.New("unable to get the state session")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	expectedState, ok := session.Values[stateSessionKey]
	if !ok {
		err = errors.New("no state ID found in state session")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if expectedState != actualState {
		err = errors.New("expected state ID does not equal actual state ID")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Extract the authorization code from the request URL.
	code := r.URL.Query().Get("code")
	if code == "" {
		err = errors.New("authorization code not found in query string")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Build the token URL.
	tokenURL, err := c.KeycloakURL("token")
	if err != nil {
		err = errors.Wrap(err, "failed to create the Keycloak token URL")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Build the redirect URL.
	redirectURL, err := url.Parse(c.frontendURL)
	if err != nil {
		err = errors.Wrap(err, "failed to parse the frontend URL")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	params := r.URL.Query()
	params.Del("code")
	params.Del("session_state")
	params.Del("state")
	params.Del("iss") // Keycloak 24+ adds issuer to callback URL
	redirectURL.RawQuery = params.Encode()
	redirectURL.Path = r.URL.Path

	// Build the form parameters.
	formParams := url.Values{}
	formParams.Set("grant_type", "authorization_code")
	formParams.Set("code", code)
	formParams.Set("redirect_uri", redirectURL.String())
	formParams.Set("client_id", c.keycloakClientID)
	formParams.Set("client_secret", c.keycloakClientSecret)

	// Attempt to get the token.
	log.Debug("attempting to exchange the authorization code for a token")
	resp, err := c.ssoClient.PostForm(tokenURL.String(), formParams)
	if err != nil {
		err = errors.Wrap(err, "failed to get the token from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Extract the token from the response.
	log.Debug("reading the response from Keycloak")
	body, err := io.ReadAll(resp.Body)
	log.Debug("finished reading the response from Keycloak")
	if err != nil {
		err = errors.Wrap(err, "failed to read the response from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the response body.
	tokenResponse := &TokenResponse{}
	err = json.Unmarshal(body, tokenResponse)
	if err != nil {
		err = errors.Wrap(err, "failed to parse the response from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tokenResponse.AccessToken == "" {
		err = errors.New("no access token found in response from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Validate the token.
	token, err := c.ValidateKeycloakToken(tokenResponse.AccessToken)
	if err != nil {
		err = errors.Wrap(err, "failed to validate token from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get the username from the token.
	username, ok := token.Get("preferred_username")
	if !ok {
		err = errors.New("no username found in the token from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check ConfigMap-based authorization: the user must be in the allowed-users list.
	usernameStr, _ := username.(string)
	if !c.isUserAllowed(usernameStr) {
		log.Errorf("user %s not in allowed-users list for analysis %s", usernameStr, c.resourceName)
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	// Store the username and Keycloak session ID in the session.
	var s *sessions.Session
	s, err = c.sessionStore.Get(r, sessionName)
	if err != nil {
		log.Warnf("failed to get session store, creating new session: %v", err)
	}
	s.Values[sessionKey] = username

	// Extract and store the Keycloak session ID for back-channel logout support.
	if sid, ok := token.Get("sid"); ok {
		sidStr, ok := sid.(string)
		if ok && sidStr != "" {
			s.Values[keycloakSidKey] = sidStr
			c.activeSessions.Store(sidStr, true)
			log.Debugf("registered active session: %s", sidStr)
		}
	}

	if err = s.Save(r, w); err != nil {
		log.Errorf("failed to save session: %v", err)
		http.Error(w, "failed to save session", http.StatusInternalServerError)
		return
	}

	// Redirect the user to the redirect URL, which was determined above.
	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
}

// RequireKeycloakAuth ensures that the user is logged in via Keycloak.
func (c *VICEProxy) RequireKeycloakAuth(w http.ResponseWriter, r *http.Request) {
	log.Debug("redirecting user to Keycloak for authentication")

	// Generate a UUID for a state ID so that we can validate it later.
	stateID, err := uuid.NewUUID()
	if err != nil {
		err = errors.Wrap(err, "failed to generate the state ID")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session, _ := c.sessionStore.Get(r, stateSessionName)
	session.Values[stateSessionKey] = stateID.String()
	err = session.Save(r, w)
	if err != nil {
		err = errors.Wrap(err, "failed to save the state ID in the session")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Build the redirect URL.
	redirectURL, err := url.Parse(c.frontendURL)
	if err != nil {
		err = errors.Wrapf(err, "failed to parse the frontend URL: %s", c.frontendURL)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectURL.Path = r.URL.Path
	redirectURL.RawQuery = r.URL.RawQuery

	// Build the login URL and set the query parameters.
	loginURL, err := c.KeycloakURL("auth")
	if err != nil {
		err = errors.Wrap(err, "failed to build the Keycloak authorization URL")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	params := loginURL.Query()
	params.Set("client_id", c.keycloakClientID)
	params.Set("state", stateID.String())
	params.Set("redirect_uri", redirectURL.String())
	params.Set("scope", "openid")
	params.Set("response_type", "code")
	loginURL.RawQuery = params.Encode()

	// Redirect the user to the login URL.
	http.Redirect(w, r, loginURL.String(), http.StatusTemporaryRedirect)
}

// ResetSessionExpiration should reset the session expiration time.
func (c *VICEProxy) ResetSessionExpiration(w http.ResponseWriter, r *http.Request) error {
	session, err := c.sessionStore.Get(r, sessionName)
	if err != nil {
		return err
	}

	msg, ok := session.Values[sessionKey]
	if !ok {
		return errors.New("session value not found")
	}

	str, ok := msg.(string)
	if !ok {
		return errors.New("session value is not a string")
	}

	session.Values[sessionKey] = str
	return session.Save(r, w)
}

// HandleLogout clears the vice-proxy session and redirects to Keycloak logout.
func (c *VICEProxy) HandleLogout(w http.ResponseWriter, r *http.Request) {
	log.Debug("handling logout request")

	// Clear the vice-proxy session and remove from active sessions
	session, err := c.sessionStore.Get(r, sessionName)
	if err != nil {
		log.Warnf("failed to get session during logout: %v", err)
	} else {
		// Remove from active sessions map if sid exists
		if sidRaw, ok := session.Values[keycloakSidKey]; ok {
			if sid, ok := sidRaw.(string); ok {
				c.activeSessions.Delete(sid)
				log.Debugf("removed session %s from active sessions", sid)
			}
		}
	}
	session.Options.MaxAge = -1 // Delete the cookie
	if err = session.Save(r, w); err != nil {
		log.Errorf("failed to save session during logout: %v", err)
	}

	// Also clear the state session
	stateSession, err := c.sessionStore.Get(r, stateSessionName)
	if err != nil {
		log.Warnf("failed to get state session during logout: %v", err)
	}
	stateSession.Options.MaxAge = -1
	if err = stateSession.Save(r, w); err != nil {
		log.Errorf("failed to save state session during logout: %v", err)
	}

	// Build the Keycloak logout URL.
	logoutURL, err := c.KeycloakURL("logout")
	if err != nil {
		log.Errorf("failed to build Keycloak logout URL: %v", err)
		http.Error(w, "logout failed", http.StatusInternalServerError)
		return
	}

	// Set the post-logout redirect to the frontend URL
	params := logoutURL.Query()
	params.Set("post_logout_redirect_uri", c.frontendURL)
	params.Set("client_id", c.keycloakClientID)
	logoutURL.RawQuery = params.Encode()

	log.Debugf("redirecting to Keycloak logout: %s", logoutURL.String())
	http.Redirect(w, r, logoutURL.String(), http.StatusTemporaryRedirect)
}

// HandleBackChannelLogout handles back-channel logout notifications from Keycloak.
// This endpoint receives a logout_token when a user logs out from Keycloak or any
// connected application. The token contains the session ID (sid) which is used to
// invalidate the local session.
func (c *VICEProxy) HandleBackChannelLogout(w http.ResponseWriter, r *http.Request) {
	log.Debug("handling back-channel logout request")

	// Parse the logout_token from the form body
	if err := r.ParseForm(); err != nil {
		log.Errorf("failed to parse form in back-channel logout: %v", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	logoutToken := r.FormValue("logout_token")
	if logoutToken == "" {
		log.Error("no logout_token in back-channel logout request")
		http.Error(w, "missing logout_token", http.StatusBadRequest)
		return
	}

	// Validate the logout token signature using Keycloak's JWKS
	token, err := c.ValidateKeycloakToken(logoutToken)
	if err != nil {
		log.Errorf("failed to validate logout token: %v", err)
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	// Verify this is a logout token by checking for the events claim
	events, ok := token.Get("events")
	if !ok {
		log.Error("logout token missing events claim")
		http.Error(w, "invalid logout token: missing events", http.StatusBadRequest)
		return
	}

	// The events claim should be a map containing the backchannel-logout event
	eventsMap, ok := events.(map[string]any)
	if !ok {
		log.Errorf("logout token events claim is not a map: %T", events)
		http.Error(w, "invalid logout token: malformed events", http.StatusBadRequest)
		return
	}

	// Check for the back-channel logout event key
	if _, ok := eventsMap["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		log.Error("logout token does not contain backchannel-logout event")
		http.Error(w, "invalid logout token: not a backchannel logout", http.StatusBadRequest)
		return
	}

	// Extract the session ID (sid) from the token
	sidRaw, ok := token.Get("sid")
	if !ok {
		log.Error("logout token missing sid claim")
		http.Error(w, "invalid logout token: missing sid", http.StatusBadRequest)
		return
	}

	sid, ok := sidRaw.(string)
	if !ok || sid == "" {
		log.Errorf("logout token sid claim is not a valid string: %T", sidRaw)
		http.Error(w, "invalid logout token: invalid sid", http.StatusBadRequest)
		return
	}

	// Invalidate the session
	c.activeSessions.Delete(sid)
	log.Infof("invalidated session %s via back-channel logout", sid)

	// Return 200 OK per the OIDC Back-Channel Logout spec
	w.WriteHeader(http.StatusOK)
}

// Session implements the mux.Matcher interface so that requests can be routed
// based on cookie existence. Returns true if authentication is required.
func (c *VICEProxy) Session(r *http.Request, m *mux.RouteMatch) bool {
	session, err := c.sessionStore.Get(r, sessionName)
	if err != nil {
		return true
	}

	msgraw, ok := session.Values[sessionKey]
	if !ok {
		return true
	}
	msg, ok := msgraw.(string)
	if !ok || msg == "" {
		log.Debug("session value was empty or not a string")
		return true
	}

	// Check if session was invalidated via back-channel logout
	if sidRaw, ok := session.Values[keycloakSidKey]; ok {
		sid, ok := sidRaw.(string)
		if !ok || sid == "" {
			log.Debug("session has invalid keycloak sid")
			return true
		}
		if _, valid := c.activeSessions.Load(sid); !valid {
			log.Debugf("session %s was invalidated via back-channel logout", sid)
			return true
		}
	}

	return false
}

// ReverseProxy returns a proxy that forwards requests to the configured
// backend URL. It can act as a http.Handler and properly handles WebSocket upgrades.
func (c *VICEProxy) ReverseProxy() (*httputil.ReverseProxy, error) {
	backend, err := url.Parse(c.backendURL)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse %s", c.backendURL)
	}

	proxy := httputil.NewSingleHostReverseProxy(backend)

	// Customize the director to handle WebSocket upgrade properly
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// For WebSocket requests, ensure proper scheme in target URL
		if c.isWebsocket(req) {
			// The backend URL stays http:// but the proxy will handle upgrade
			log.Infof("WebSocket upgrade request detected for %s", req.URL.Path)
		}
	}

	return proxy, nil
}

// isWebsocket returns true if the request is a WebSocket upgrade request. Adapted
// from https://groups.google.com/d/msg/golang-nuts/KBx9pDlvFOc/0tR1gBRfFVMJ.
func (c *VICEProxy) isWebsocket(r *http.Request) bool {
	connection := r.Header.Get("Connection")
	if !strings.Contains(strings.ToLower(connection), "upgrade") {
		return false
	}
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// backendIsReady returns true when the backend responds with a 2xx or 3xx status.
// Uses http.Get without a context because this is a health-check polling call
// with no ambient request context; the server-level ReadTimeout bounds it.
//
//nolint:noctx // no request context available in health-check polling
func (c *VICEProxy) backendIsReady(backendURL string) (bool, error) {
	resp, err := http.Get(backendURL) //nolint:noctx
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body) // drain so the connection can be reused

	return resp.StatusCode >= 200 && resp.StatusCode < 400, nil
}

// URLIsReady will write out a JSON-encoded response in the format
// {"ready":boolean}, telling whether or not the underlying application is ready
// for business yet.
func (c *VICEProxy) URLIsReady(w http.ResponseWriter, r *http.Request) {
	log.Infof("checking backend readiness at %s", c.backendURL)
	ready, err := c.backendIsReady(c.backendURL)
	if err != nil {
		log.Errorf("backend readiness check failed: %v", err)
	}

	log.Infof("backend ready status: %v", ready)

	data := map[string]bool{
		"ready": ready,
	}

	body, err := json.Marshal(data)
	if err != nil {
		log.Errorf("failed to marshal readiness response: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ready {
		_, _ = w.Write(body)
	} else {
		http.Error(w, string(body), http.StatusNotAcceptable)
	}
}

// FrontendURL returns the configured frontend URL as JSON. Called by
// app-exposer via the in-cluster Service to discover the access URL.
func (c *VICEProxy) FrontendURL(w http.ResponseWriter, r *http.Request) {
	body, err := json.Marshal(map[string]string{"url": c.frontendURL})
	if err != nil {
		log.Errorf("failed to encode frontend URL response: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// GetFrontendHost returns the host and port portions of the resource name.
func (c *VICEProxy) GetFrontendHost() (string, error) {
	svcURL, err := url.Parse(c.frontendURL)
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse the frontend URL %s", c.frontendURL)
	}

	return svcURL.Host, nil
}

// authenticateAndAuthorize validates the user's session and checks if they have permission
// to access the resource via the ConfigMap-based allowed-users list.
// Returns the username on success, or an error on failure.
func (c *VICEProxy) authenticateAndAuthorize(w http.ResponseWriter, r *http.Request) (string, error) {
	// Get the username from the cookie
	session, err := c.sessionStore.Get(r, sessionName)
	if err != nil {
		return "", errors.Wrap(err, "failed to get session")
	}

	// Check if the session contains a username
	usernameValue, ok := session.Values[sessionKey]
	if !ok || usernameValue == nil {
		return "", errors.New("no session found")
	}

	username, ok := usernameValue.(string)
	if !ok || username == "" {
		return "", errors.New("username was empty or invalid")
	}
	log.Infof("authenticated user: %s", username)

	// Check if session was invalidated via back-channel logout.
	// This mirrors the check in Session() (the mux.Matcher) as defense-in-depth:
	// Session() guards the route match, but authenticateAndAuthorize guards the
	// proxied request itself, which may arrive via a route that bypasses Session().
	if sidRaw, ok := session.Values[keycloakSidKey]; ok {
		sid, ok := sidRaw.(string)
		if !ok || sid == "" {
			return "", errors.New("invalid session ID in cookie")
		}
		if _, valid := c.activeSessions.Load(sid); !valid {
			log.Infof("session %s was invalidated via back-channel logout", sid)
			return "", errors.New("session invalidated")
		}
	}

	// Check ConfigMap-based authorization: the user must be in the allowed-users list.
	if !c.isUserAllowed(username) {
		return "", fmt.Errorf("user %s is not in the allowed-users list", username)
	}

	// CRITICAL: Don't reset session for WebSocket upgrades (would corrupt the upgrade handshake)
	if !c.isWebsocket(r) {
		if err = c.ResetSessionExpiration(w, r); err != nil {
			return "", errors.Wrap(err, "error resetting session expiration")
		}
	}

	return username, nil
}

// Proxy returns a handler that can support both websockets and http requests.
func (c *VICEProxy) Proxy() (http.Handler, error) {
	rp, err := c.ReverseProxy()
	if err != nil {
		return nil, err
	}

	frontendHost, err := c.GetFrontendHost()
	if err != nil {
		return nil, err
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Infof("handling request for %s from remote address %s", r.URL.String(), r.RemoteAddr)

		// Conditionally perform authentication and authorization
		if !c.disableAuth {
			username, err := c.authenticateAndAuthorize(w, r)
			if err != nil {
				log.Errorf("auth/authz error: %v", err)
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			log.Debugf("request authorized for user: %s", username)
		} else {
			log.Debug("authentication disabled, allowing unauthenticated access")
		}

		// Override the X-Forwarded-Host header.
		r.Header.Set("X-Forwarded-Host", frontendHost)

		// The reverse proxy handles both HTTP and WebSocket upgrade requests transparently
		log.Infof("proxying request to %s%s", c.backendURL, r.URL.Path)
		rp.ServeHTTP(w, r)
	}), nil
}

type originFlags []string

func (o *originFlags) String() string {
	return strings.Join([]string(*o), ",")
}

func (o *originFlags) Set(s string) error {
	parts := strings.Split(s, ",")
	*o = append(*o, parts...)
	return nil
}

func main() {
	logrus.SetReportCaller(true)
	logrus.SetLevel(logrus.InfoLevel)

	// Per-pod flags — injected by the vice-operator transform.
	var (
		backendURL          = flag.String("backend-url", "http://localhost:60000", "The hostname and port to proxy requests to.")
		wsbackendURL        = flag.String("ws-backend-url", "", "The backend URL for the handling websocket requests. Defaults to the value of --backend-url with a scheme of ws://")
		listenAddr          = flag.String("listen-addr", "0.0.0.0:8080", "The listen port number.")
		analysisID          = flag.String("analysis-id", "", "The UUID of the analysis to use for authorization.")
		maxAge              = flag.Int("max-age", 0, "The idle timeout for session, in seconds.")
		sslCert             = flag.String("ssl-cert", "", "Path to the SSL .crt file.")
		sslKey              = flag.String("ssl-key", "", "Path to the SSL .key file.")
		encodedSSOTimeout   = flag.String("sso-timeout", "5s", "The timeout period for back-channel requests to the identity provider.")
		encodedReadTimeout  = flag.String("read-timeout", "48h", "The maximum duration for reading the entire request, including the body.")
		encodedWriteTimeout = flag.String("write-timeout", "48h", "The maximum duration before timing out writes of the response.")
		encodedIdleTimeout  = flag.String("idle-timeout", "5000s", "The maximum amount of time to wait for the next request when keep-alives are enabled.")
		encodedJWKSCacheTTL = flag.String("jwks-cache-ttl", "1h", "How long to cache Keycloak JWKS certificates. Set to 0 to disable caching.")
	)

	flag.Parse()

	// Cluster-specific config from env vars (via cluster-config-secret).
	keycloakBaseURL := os.Getenv("KEYCLOAK_BASE_URL")
	keycloakRealm := os.Getenv("KEYCLOAK_REALM")
	keycloakClientID := os.Getenv("KEYCLOAK_CLIENT_ID")
	keycloakClientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET")
	disableAuth := strings.EqualFold(os.Getenv("DISABLE_AUTH"), "true")

	// Derive frontendURL from VICE_BASE_URL env var. The pod hostname is the
	// subdomain hash set by app-exposer, so combining it with the base URL
	// produces the full analysis URL.
	var frontendURL string
	if baseURL := os.Getenv("VICE_BASE_URL"); baseURL != "" {
		hostname, err := os.Hostname()
		if err != nil {
			log.Fatalf("failed to get hostname for VICE_BASE_URL: %v", err)
		}
		parsedBase, err := url.Parse(baseURL)
		if err != nil {
			log.Fatalf("failed to parse VICE_BASE_URL %q: %v", baseURL, err)
		}
		parsedBase.Host = fmt.Sprintf("%s.%s", hostname, parsedBase.Host)
		frontendURL = parsedBase.String()
		log.Infof("derived frontend URL from VICE_BASE_URL: %s", frontendURL)
	}

	if frontendURL == "" {
		log.Fatal("VICE_BASE_URL env var must be set")
	}

	useSSL := false
	if *sslCert != "" || *sslKey != "" {
		if *sslCert == "" {
			log.Fatal("--ssl-cert is required with --ssl-key.")
		}

		if *sslKey == "" {
			log.Fatal("--ssl-key is required with --ssl-cert.")
		}
		useSSL = true
	}

	// Derive CORS origins from VICE_BASE_URL domain.
	var corsOrigins originFlags
	if viceBase := os.Getenv("VICE_BASE_URL"); viceBase != "" {
		if parsedBase, err := url.Parse(viceBase); err == nil && parsedBase.Host != "" {
			corsOrigins = originFlags{
				fmt.Sprintf("*.%s", parsedBase.Host),
				parsedBase.Host,
			}
		} else {
			log.Warnf("VICE_BASE_URL %q could not be parsed for CORS origins, using defaults", viceBase)
		}
	}
	if len(corsOrigins) < 1 {
		corsOrigins = originFlags{"*.cyverse.run", "*.cyverse.org", "*.cyverse.run:4343", "cyverse.run", "cyverse.run:4343"}
	}

	if *analysisID == "" {
		log.Fatal("--analysis-id must be set.")
	}

	log.Infof("backend URL is %s", *backendURL)
	log.Infof("websocket backend URL is %s", *wsbackendURL)
	log.Infof("frontend URL is %s", frontendURL)
	log.Infof("listen address is %s", *listenAddr)
	log.Infof("Keycloak base URL is %s", keycloakBaseURL)
	log.Infof("Keycloak realm is %s", keycloakRealm)
	log.Infof("Keycloak client ID is %s", keycloakClientID)
	log.Infof("Keycloak client secret is set: %v", keycloakClientSecret != "")
	log.Infof("read timeout is %s", *encodedReadTimeout)
	log.Infof("write timeout is %s", *encodedWriteTimeout)
	log.Infof("idle timeout is %s", *encodedIdleTimeout)
	log.Infof("authentication disabled: %v", disableAuth)

	for _, origin := range corsOrigins {
		log.Infof("CORS origin: %s", origin)
	}

	authkey := make([]byte, 64)
	_, err := rand.Read(authkey)
	if err != nil {
		log.Fatal(err)
	}

	sessionStore := sessions.NewCookieStore(authkey)
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   *maxAge,
		HttpOnly: true,
	}

	// Decode the timeout duration for back-channel requests to the identity provider.
	ssoTimeout, err := time.ParseDuration(*encodedSSOTimeout)
	if err != nil {
		log.Fatalf("invalid timeout duration for back-channel requests to the IdP: %s", err.Error())
	}

	// Decode the timeout durations for the HTTP server.
	readTimeout, err := time.ParseDuration(*encodedReadTimeout)
	if err != nil {
		log.Fatalf("invalid read timeout duration: %s", err.Error())
	}

	writeTimeout, err := time.ParseDuration(*encodedWriteTimeout)
	if err != nil {
		log.Fatalf("invalid write timeout duration: %s", err.Error())
	}

	idleTimeout, err := time.ParseDuration(*encodedIdleTimeout)
	if err != nil {
		log.Fatalf("invalid idle timeout duration: %s", err.Error())
	}

	// Create an HTTP client to use for back-channel requests to the identity provider.
	client := &http.Client{
		Timeout: ssoTimeout,
	}

	// Parse the JWKS cache TTL.
	jwksCacheTTL, err := time.ParseDuration(*encodedJWKSCacheTTL)
	if err != nil {
		log.Fatalf("invalid JWKS cache TTL duration: %s", err.Error())
	}

	p := &VICEProxy{
		keycloakBaseURL:      keycloakBaseURL,
		keycloakRealm:        keycloakRealm,
		keycloakClientID:     keycloakClientID,
		keycloakClientSecret: keycloakClientSecret,
		frontendURL:          frontendURL,
		backendURL:           *backendURL,
		wsbackendURL:         *wsbackendURL,
		resourceName:         *analysisID,
		sessionStore:         sessionStore,
		ssoClient:            *client,
		disableAuth:          disableAuth,
	}

	// Load the initial allowed-users list from the permissions ConfigMap mount.
	// If the file doesn't exist yet (e.g. in dev), log an error but continue —
	// the watcher will pick it up when the volume is mounted.
	if !disableAuth {
		count, err := p.loadAllowedUsers(permissionsFilePath)
		if err != nil {
			log.Errorf("could not load initial permissions: %v", err)
		} else {
			log.Infof("loaded %d allowed users from %s", count, permissionsFilePath)
		}
		if err := p.watchPermissionsFile(permissionsFilePath); err != nil {
			log.Fatalf("permissions file watcher failed (proxy cannot pick up permission changes): %v", err)
		}
	}

	// Set up JWKS caching if auth is enabled and TTL is positive.
	if !disableAuth && jwksCacheTTL > 0 {
		certsURL, err := p.KeycloakURL("certs")
		if err != nil {
			log.Fatalf("failed to build Keycloak certs URL: %s", err.Error())
		}
		p.jwksCertsURL = certsURL.String()

		ar := jwk.NewAutoRefresh(context.Background())
		ar.Configure(p.jwksCertsURL, jwk.WithMinRefreshInterval(jwksCacheTTL))

		p.jwksAutoRefresh = ar
		log.Infof("JWKS caching enabled with minimum refresh interval of %s", jwksCacheTTL)
	} else if !disableAuth {
		log.Info("JWKS caching disabled, certificates will be fetched on every token validation")
	}

	proxy, err := p.Proxy()
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()

	// Unauthenticated endpoints — health check and internal info.
	r.PathPrefix("/url-ready").HandlerFunc(p.URLIsReady)
	r.Path("/frontend-url").Methods(http.MethodGet).HandlerFunc(p.FrontendURL)

	// Back-channel logout endpoint - receives logout notifications from Keycloak
	// This must be available even if auth is disabled, as it's called by Keycloak/app-exposer
	r.Path("/backchannel-logout").Methods("POST").HandlerFunc(p.HandleBackChannelLogout)

	// Conditionally add authentication routes based on DISABLE_AUTH env var.
	if !disableAuth {
		// Logout endpoint - clears session and redirects to Keycloak logout
		r.Path("/logout").HandlerFunc(p.HandleLogout)
		// If the query contains a code parameter, handle the OAuth authorization code
		r.PathPrefix("/").Queries("code", "").Handler(http.HandlerFunc(p.HandleAuthorizationCode))
		// If the request doesn't have a valid session, redirect to Keycloak for authentication
		r.PathPrefix("/").MatcherFunc(p.Session).Handler(http.HandlerFunc(p.RequireKeycloakAuth))
	}

	// Proxy all requests to the backend
	r.PathPrefix("/").Handler(proxy)

	c := cors.New(cors.Options{
		AllowedOrigins:   corsOrigins,
		AllowCredentials: true,
	})

	server := &http.Server{
		Handler:      c.Handler(r),
		Addr:         *listenAddr,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}
	if useSSL {
		err = server.ListenAndServeTLS(*sslCert, *sslKey)
	} else {
		err = server.ListenAndServe()
	}
	log.Fatal(err)
}
