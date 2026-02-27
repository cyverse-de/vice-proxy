package main

import (
	"bytes"
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
	"strings"
	"sync"
	"time"

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

const stateSessionName = "state-session"
const stateSessionKey = "state-session-key"
const sessionName = "proxy-session"
const sessionKey = "proxy-session-key"
const keycloakSidKey = "keycloak-sid"

// VICEProxy contains the application logic that handles authentication, session
// validations, ticket validation, and request proxying.
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
	disableAuth             bool                  // If true, authentication and authorization are disabled.
	enableLegacyAuth        bool                  // If true, use per-request check-resource-access instead of Keycloak UMA.
	checkResourceAccessBase string                // Base URL for the check-resource-access service (legacy mode).
	jwksAutoRefresh         *jwk.AutoRefresh      // Cached JWKS fetcher, nil if caching is disabled.
	jwksCertsURL            string                // The resolved JWKS certs URL, set during initialization.
	activeSessions          sync.Map              // Tracks valid Keycloak session IDs for back-channel logout.
}

// Resource is an item that can have permissions attached to it in the
// permissions service.
type Resource struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"resource_type"`
}

// Subject is an item that accesses resources contained in the permissions
// service.
type Subject struct {
	ID        string `json:"id"`
	SubjectID string `json:"subject_id"`
	SourceID  string `json:"subject_source_id"`
	Type      string `json:"subject_type"`
}

// Permission is an entry from the permissions service that tells what access
// a subject has to a resource.
type Permission struct {
	ID       string   `json:"id"`
	Level    string   `json:"permission_level"`
	Resource Resource `json:"resource"`
	Subject  Subject  `json:"subject"`
}

// PermissionList contains a list of permissions returned by the permissions
// service.
type PermissionList struct {
	Permissions []Permission `json:"permissions"`
}

// IsAllowed returns true if the user has permission to access the resource
// via the check-resource-access service. Used in legacy auth mode only.
func (c *VICEProxy) IsAllowed(user, resource string) (bool, error) {
	bodymap := map[string]string{
		"subject":  user,
		"resource": resource,
	}

	body, err := json.Marshal(bodymap)
	if err != nil {
		return false, err
	}

	request, err := http.NewRequest(http.MethodPost, c.checkResourceAccessBase, bytes.NewReader(body))
	if err != nil {
		return false, err
	}

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	l := &PermissionList{
		Permissions: []Permission{},
	}

	if err = json.Unmarshal(b, l); err != nil {
		return false, err
	}

	if len(l.Permissions) > 0 {
		if l.Permissions[0].Level != "" {
			return true, nil
		}
	}

	return false, nil
}

// KeycloakURL generates a URL that we can use for Keycloak.
func (c *VICEProxy) KeycloakURL(components ...string) (*url.URL, error) {
	keycloakURL, err := url.Parse(c.keycloakBaseURL)
	if err != nil {
		return nil, err
	}

	// Add the known parts of the URL.
	cs := append(
		[]string{keycloakURL.Path, "realms", c.keycloakRealm, "protocol", "openid-connect"},
		components...,
	)
	keycloakURL.Path = strings.Join(cs, "/")

	return keycloakURL, nil
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

// CheckKeycloakAuthorization requests a UMA RPT (Requesting Party Token) from Keycloak
// to verify that the user has access to the analysis resource. Keycloak evaluates the
// configured authorization policies (including the vice-access policy provider) and
// returns a token if access is granted.
func (c *VICEProxy) CheckKeycloakAuthorization(accessToken string) error {
	tokenURL, err := c.KeycloakURL("token")
	if err != nil {
		return errors.Wrap(err, "failed to build Keycloak token URL for UMA check")
	}

	formParams := url.Values{}
	formParams.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	formParams.Set("audience", c.keycloakClientID)
	formParams.Set("permission", c.resourceName+"#access")

	req, err := http.NewRequest(http.MethodPost, tokenURL.String(), strings.NewReader(formParams.Encode()))
	if err != nil {
		return errors.Wrap(err, "failed to create UMA authorization request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.ssoClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send UMA authorization request to Keycloak")
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain the body so the connection can be reused.
	_, _ = io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("keycloak denied access to resource %s (HTTP %d)", c.resourceName, resp.StatusCode)
	}

	return nil
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
	//log.Debugf("state query parameter value: %s", actualState)
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
	//log.Debugf("expected state value: %s", expectedState)
	if expectedState != actualState {
		err = errors.New("expected state ID does not equal actual state ID")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Extract the authorization code from the request URL.
	code := r.URL.Query().Get("code")
	//log.Debugf("authorization code: %s", code)
	if code == "" {
		err = errors.New("authorization code not found in query string")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Build the token URL.
	tokenURL, err := c.KeycloakURL("token")
	//log.Debugf("token URL: %s", tokenURL.String())
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
	//log.Debugf("redirect URL: %s", redirectURL.String())

	// Build the form parameters.
	formParams := url.Values{}
	formParams.Set("grant_type", "authorization_code")
	formParams.Set("code", code)
	formParams.Set("redirect_uri", redirectURL.String())
	formParams.Set("client_id", c.keycloakClientID)
	formParams.Set("client_secret", c.keycloakClientSecret)
	//log.Debugf("form params: %s", formParams.Encode())

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
		err = fmt.Errorf("no access token found in response from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//log.Debugf("access token: %s", tokenResponse.AccessToken)

	// Validate the token.
	token, err := c.ValidateKeycloakToken(tokenResponse.AccessToken)
	if err != nil {
		err = errors.Wrap(err, "failed to validate token from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check authorization via Keycloak UMA unless legacy auth is enabled.
	// In legacy mode, authorization is deferred to per-request IsAllowed() checks.
	if !c.enableLegacyAuth {
		if err := c.CheckKeycloakAuthorization(tokenResponse.AccessToken); err != nil {
			log.Errorf("UMA authorization denied: %v", err)
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}
	} else {
		log.Debug("legacy auth enabled, skipping UMA authorization check at login")
	}

	// Get the username from the token.
	username, ok := token.Get("preferred_username")
	if !ok {
		err = fmt.Errorf("no username found in the token from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	//log.Debugf("redirecting the user to: %s", redirectURL.String())
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
	//log.Debugf("generated state ID: %s", stateID.String())

	// Build the redirect URL.
	redirectURL, err := url.Parse(c.frontendURL)
	if err != nil {
		err = errors.Wrapf(err, "failed to parse the frontend URL: %s", c.frontendURL)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectURL.Path = r.URL.Path
	redirectURL.RawQuery = r.URL.RawQuery
	//log.Debugf("redirect URL: %s", redirectURL.String())

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
	//log.Debugf("redirecting the user to %s", loginURL.String())
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

	// Build the Keycloak logout URL
	logoutURL, err := url.Parse(c.keycloakBaseURL)
	if err != nil {
		log.Errorf("failed to parse Keycloak base URL for logout: %v", err)
		http.Error(w, "logout failed", http.StatusInternalServerError)
		return
	}
	logoutURL.Path = fmt.Sprintf("/realms/%s/protocol/openid-connect/logout", c.keycloakRealm)

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

	if r.Method != http.MethodPost {
		log.Errorf("back-channel logout requires POST method, got %s", r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

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
	eventsMap, ok := events.(map[string]interface{})
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

// isWebsocket returns true if the connection is a websocket request. Adapted
// from the code at https://groups.google.com/d/msg/golang-nuts/KBx9pDlvFOc/0tR1gBRfFVMJ.
func (c *VICEProxy) isWebsocket(r *http.Request) bool {
	connectionHeader := ""
	allHeaders := r.Header["Connection"]
	if len(allHeaders) > 0 {
		connectionHeader = allHeaders[0]
	}

	upgrade := false
	if strings.Contains(strings.ToLower(connectionHeader), "upgrade") {
		if len(r.Header["Upgrade"]) > 0 {
			upgrade = (strings.ToLower(r.Header["Upgrade"][0]) == "websocket")
		}
	}
	return upgrade
}

func (c *VICEProxy) backendIsReady(backendURL string) (bool, error) {
	resp, err := http.Get(backendURL)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body) // drain so connection can be reused

	if resp.StatusCode >= 200 && resp.StatusCode <= 399 {
		return true, nil
	}
	return false, nil

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
		_, _ = fmt.Fprint(w, string(body))
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
// to access the resource. Returns the username on success, or an error on failure.
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

	// Check if session was invalidated via back-channel logout
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

	// In legacy mode, check permissions per-request via the check-resource-access service.
	// In default (Keycloak UMA) mode, authorization was already checked at login.
	if c.enableLegacyAuth {
		allowed, err := c.IsAllowed(username, c.resourceName)
		if err != nil {
			return "", errors.Wrap(err, "legacy permission check failed")
		}
		if !allowed {
			return "", fmt.Errorf("user %s is not allowed to access %s", username, c.resourceName)
		}
		log.Infof("legacy auth: user %s authorized for resource %s", username, c.resourceName)
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

	var (
		corsOrigins             originFlags
		backendURL              = flag.String("backend-url", "http://localhost:60000", "The hostname and port to proxy requests to.")
		wsbackendURL            = flag.String("ws-backend-url", "", "The backend URL for the handling websocket requests. Defaults to the value of --backend-url with a scheme of ws://")
		frontendURL             = flag.String("frontend-url", "", "The URL for the frontend server. Might be different from the hostname and listen port.")
		listenAddr              = flag.String("listen-addr", "0.0.0.0:8080", "The listen port number.")
		keycloakBaseURL         = flag.String("keycloak-base-url", "", "The base URL to use when checking Keycloak authentication.")
		keycloakRealm           = flag.String("keycloak-realm", "", "The realm to use when checking Keycloak authentication.")
		keycloakClientID        = flag.String("keycloak-client-id", "", "The ID of the OIDC client to use for Keycloak.")
		keycloakClientSecret    = flag.String("keycloak-client-secret", "", "The secret of the OIDC client to use for Keycloak.")
		maxAge                  = flag.Int("max-age", 0, "The idle timeout for session, in seconds.")
		sslCert    = flag.String("ssl-cert", "", "Path to the SSL .crt file.")
		sslKey     = flag.String("ssl-key", "", "Path to the SSL .key file.")
		analysisID = flag.String("analysis-id", "", "The UUID of the analysis to use for authorization.")
		encodedSSOTimeout       = flag.String("sso-timeout", "5s", "The timeout period for back-channel requests to the identity provider.")
		encodedReadTimeout      = flag.String("read-timeout", "48h", "The maximum duration for reading the entire request, including the body.")
		encodedWriteTimeout     = flag.String("write-timeout", "48h", "The maximum duration before timing out writes of the response.")
		encodedIdleTimeout      = flag.String("idle-timeout", "5000s", "The maximum amount of time to wait for the next request when keep-alives are enabled.")
		disableAuth             = flag.Bool("disable-auth", false, "Disable authentication and authorization. When true, allows unauthenticated access to the proxied application.")
		enableLegacyAuth        = flag.Bool("enable-legacy-auth", false, "Use per-request check-resource-access calls instead of Keycloak UMA authorization.")
		checkResourceAccessBase = flag.String("check-resource-access-base", "http://check-resource-access", "Base URL for the check-resource-access service (legacy auth mode).")
		encodedJWKSCacheTTL     = flag.String("jwks-cache-ttl", "1h", "How long to cache Keycloak JWKS certificates. Set to 0 to disable caching.")
	)

	flag.Var(&corsOrigins, "allowed-origins", "List of allowed origins, separated by commas.")
	flag.Parse()

	// Derive frontendURL from VICE_BASE_URL env var if set. The pod hostname
	// is the subdomain hash set by app-exposer, so combining it with the base
	// URL produces the full analysis URL.
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
		*frontendURL = parsedBase.String()
		log.Infof("derived frontend URL from VICE_BASE_URL: %s", *frontendURL)
	}

	if *frontendURL == "" {
		log.Fatal("--frontend-url must be set.")
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

	if len(corsOrigins) < 1 {
		corsOrigins = originFlags{"*.cyverse.run", "*.cyverse.org", "*.cyverse.run:4343", "cyverse.run", "cyverse.run:4343"}
	}

	if *analysisID == "" {
		log.Fatal("--analysis-id must be set.")
	}

	log.Infof("backend URL is %s", *backendURL)
	log.Infof("websocket backend URL is %s", *wsbackendURL)
	log.Infof("frontend URL is %s", *frontendURL)
	log.Infof("listen address is %s", *listenAddr)
	log.Infof("Keycloak base URL is %s", *keycloakBaseURL)
	log.Infof("Keycloak realm is %s", *keycloakRealm)
	log.Infof("Keycloak client ID is %s", *keycloakClientID)
	log.Infof("Keycloak client secret is %s", *keycloakClientSecret)
	log.Infof("read timeout is %s", *encodedReadTimeout)
	log.Infof("write timeout is %s", *encodedWriteTimeout)
	log.Infof("idle timeout is %s", *encodedIdleTimeout)
	log.Infof("authentication disabled: %v", *disableAuth)
	log.Infof("legacy auth enabled: %v", *enableLegacyAuth)
	if *enableLegacyAuth {
		log.Infof("check-resource-access base URL: %s", *checkResourceAccessBase)
	}

	for _, c := range corsOrigins {
		log.Infof("Origin: %s\n", c)
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
		keycloakBaseURL:         *keycloakBaseURL,
		keycloakRealm:           *keycloakRealm,
		keycloakClientID:        *keycloakClientID,
		keycloakClientSecret:    *keycloakClientSecret,
		frontendURL:             *frontendURL,
		backendURL:              *backendURL,
		wsbackendURL:            *wsbackendURL,
		resourceName:            *analysisID,
		sessionStore:            sessionStore,
		ssoClient:               *client,
		disableAuth:             *disableAuth,
		enableLegacyAuth:        *enableLegacyAuth,
		checkResourceAccessBase: *checkResourceAccessBase,
	}

	// Set up JWKS caching if auth is enabled and TTL is positive.
	if !*disableAuth && jwksCacheTTL > 0 {
		certsURL, err := p.KeycloakURL("certs")
		if err != nil {
			log.Fatalf("failed to build Keycloak certs URL: %s", err.Error())
		}
		p.jwksCertsURL = certsURL.String()

		ar := jwk.NewAutoRefresh(context.Background())
		ar.Configure(p.jwksCertsURL, jwk.WithMinRefreshInterval(jwksCacheTTL))

		p.jwksAutoRefresh = ar
		log.Infof("JWKS caching enabled with minimum refresh interval of %s", jwksCacheTTL)
	} else if !*disableAuth {
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

	// Conditionally add authentication routes based on --disable-auth flag
	if !*disableAuth {
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
