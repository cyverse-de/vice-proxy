package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// getVICEProxy returns a VICEProxy instance with some default settnigs for testing. Some fields that aren't being used
// during testing are omitted.
func getVICEProxy() *VICEProxy {
	return &VICEProxy{
		casBase:                 "https://cas.example.org/cas",
		casValidate:             "validate",
		keycloakBaseURL:         "https://keycloak.example.org",
		keycloakRealm:           "example",
		keycloakClientID:        "example-client",
		keycloakClientSecret:    "example-secret",
		frontendURL:             "https://foobarbaz.example.run",
		backendURL:              "http://localhost:8888",
		wsbackendURL:            "http://localhost:8888",
		getAnalysisIDBase:       "http://get-analysis-id",
		checkResourceAccessBase: "http://check-resource-access",
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
