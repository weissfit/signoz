package oidccallbackauthn

import (
	"testing"

	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/stretchr/testify/assert"
)

func defaultMapping(t *testing.T) authtypes.AttributeMapping {
	t.Helper()

	var mapping authtypes.AttributeMapping
	assert.NoError(t, mapping.UnmarshalJSON([]byte("{}")))
	return mapping
}

func TestMapIdentity(t *testing.T) {
	testCases := []struct {
		name          string
		claims        map[string]any
		mapping       authtypes.AttributeMapping
		expectedName  string
		expectedEmail string
		expectedGroup []string
		expectedRole  string
	}{
		{
			name: "DefaultKeys",
			claims: map[string]any{
				"name":  "Jane Doe",
				"email": "jane@example.com",
			},
			mapping:       defaultMapping(t),
			expectedName:  "Jane Doe",
			expectedEmail: "jane@example.com",
		},
		{
			name: "CustomKeys",
			claims: map[string]any{
				"preferred_username": "jane@example.com",
				"full_name":          "Jane Doe",
				"custom_role":        "admin",
				"custom_groups":      []any{"admins"},
			},
			mapping: authtypes.AttributeMapping{
				Email:  "preferred_username",
				Name:   "full_name",
				Role:   "custom_role",
				Groups: "custom_groups",
			},
			expectedName:  "Jane Doe",
			expectedEmail: "jane@example.com",
			expectedRole:  "admin",
			expectedGroup: []string{"admins"},
		},
		{
			name: "GroupsAsArray",
			claims: map[string]any{
				"groups": []any{"admins", "viewers"},
			},
			mapping:       defaultMapping(t),
			expectedGroup: []string{"admins", "viewers"},
		},
		{
			name: "GroupsAsString",
			claims: map[string]any{
				"groups": "admins",
			},
			mapping:       defaultMapping(t),
			expectedGroup: []string{"admins"},
		},
		{
			name:          "GroupsAbsent",
			claims:        map[string]any{},
			mapping:       defaultMapping(t),
			expectedGroup: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			name, email, groups, role := mapIdentity(tc.claims, tc.mapping)

			assert.Equal(t, tc.expectedName, name)
			assert.Equal(t, tc.expectedEmail, email)
			assert.Equal(t, tc.expectedGroup, groups)
			assert.Equal(t, tc.expectedRole, role)
		})
	}
}

func TestIsEmailVerified(t *testing.T) {
	testCases := []struct {
		name                      string
		claims                    map[string]any
		insecureSkipEmailVerified bool
		expected                  bool
	}{
		{
			name:     "VerifiedTrue",
			claims:   map[string]any{"email_verified": true},
			expected: true,
		},
		{
			name:     "VerifiedFalse",
			claims:   map[string]any{"email_verified": false},
			expected: false,
		},
		{
			name:     "VerifiedAbsent",
			claims:   map[string]any{},
			expected: false,
		},
		{
			name:     "VerifiedTrueAsString",
			claims:   map[string]any{"email_verified": "true"},
			expected: true,
		},
		{
			name:     "VerifiedFalseAsString",
			claims:   map[string]any{"email_verified": "false"},
			expected: false,
		},
		{
			name:                      "VerifiedFalseButInsecureSkip",
			claims:                    map[string]any{"email_verified": false},
			insecureSkipEmailVerified: true,
			expected:                  true,
		},
		{
			name:                      "VerifiedAbsentButInsecureSkip",
			claims:                    map[string]any{},
			insecureSkipEmailVerified: true,
			expected:                  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isEmailVerified(tc.claims, tc.insecureSkipEmailVerified))
		})
	}
}

func TestMergeClaims(t *testing.T) {
	testCases := []struct {
		name           string
		idTokenClaims  map[string]any
		userInfoClaims map[string]any
		emailKey       string
		expectedMerged map[string]any
	}{
		{
			name:          "UserInfoOverlaysNonEmailClaims",
			idTokenClaims: map[string]any{"email": "id@example.com", "name": "Jane", "email_verified": true},
			userInfoClaims: map[string]any{
				"email":  "id@example.com",
				"groups": []any{"admins"},
			},
			emailKey: "email",
			expectedMerged: map[string]any{
				"email":          "id@example.com",
				"name":           "Jane",
				"email_verified": true,
				"groups":         []any{"admins"},
			},
		},
		{
			name:           "EmailChangedWithoutVerifiedDropsStaleVerified",
			idTokenClaims:  map[string]any{"email": "id@example.com", "name": "Jane", "email_verified": true},
			userInfoClaims: map[string]any{"email": "userinfo@example.com"},
			emailKey:       "email",
			expectedMerged: map[string]any{
				"email": "userinfo@example.com",
				"name":  "Jane",
			},
		},
		{
			name:           "EmailChangedWithVerifiedKeepsUserInfoVerified",
			idTokenClaims:  map[string]any{"email": "id@example.com", "name": "Jane", "email_verified": true},
			userInfoClaims: map[string]any{"email": "userinfo@example.com", "email_verified": false},
			emailKey:       "email",
			expectedMerged: map[string]any{
				"email":          "userinfo@example.com",
				"name":           "Jane",
				"email_verified": false,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			merged := mergeClaims(tc.idTokenClaims, tc.userInfoClaims, tc.emailKey)
			assert.Equal(t, tc.expectedMerged, merged)
		})
	}
}
