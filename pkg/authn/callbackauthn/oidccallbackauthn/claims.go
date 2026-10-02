package oidccallbackauthn

import (
	"strconv"

	"github.com/SigNoz/signoz/pkg/types/authtypes"
)

// emailVerifiedClaim is a fixed claim key, unlike the rest of the mapping which is
// configurable via AttributeMapping.
const emailVerifiedClaim = "email_verified"

// mapIdentity pulls name/email/groups/role out of claims by the keys named in mapping.
func mapIdentity(claims map[string]any, mapping authtypes.AttributeMapping) (name string, email string, groups []string, role string) {
	return stringClaim(claims, mapping.Name), stringClaim(claims, mapping.Email), normalizeGroups(claims[mapping.Groups]), stringClaim(claims, mapping.Role)
}

// isEmailVerified fails closed: a missing or false email_verified claim is treated as
// unverified unless insecureSkipEmailVerified opts out of the check entirely. Some IdPs
// (e.g. AWS Cognito) encode email_verified as the string "true"/"false" rather than a
// JSON boolean, so both forms are accepted.
func isEmailVerified(claims map[string]any, insecureSkipEmailVerified bool) bool {
	if insecureSkipEmailVerified {
		return true
	}

	switch v := claims[emailVerifiedClaim].(type) {
	case bool:
		return v
	case string:
		verified, _ := strconv.ParseBool(v)
		return verified
	default:
		return false
	}
}

// mergeClaims overlays userInfoClaims onto idTokenClaims, userinfo winning on conflicts.
// If userinfo changes the email without also supplying email_verified, the ID token's
// email_verified is dropped rather than carried over, since it attests to the old
// address, not the new one.
func mergeClaims(idTokenClaims, userInfoClaims map[string]any, emailKey string) map[string]any {
	merged := make(map[string]any, len(idTokenClaims)+len(userInfoClaims))
	for k, v := range idTokenClaims {
		merged[k] = v
	}

	if newEmail, ok := userInfoClaims[emailKey]; ok && newEmail != idTokenClaims[emailKey] {
		if _, hasVerified := userInfoClaims[emailVerifiedClaim]; !hasVerified {
			delete(merged, emailVerifiedClaim)
		}
	}

	for k, v := range userInfoClaims {
		merged[k] = v
	}

	return merged
}

func stringClaim(claims map[string]any, key string) string {
	s, _ := claims[key].(string)
	return s
}

// normalizeGroups handles the groups claim being absent, a single string, or a JSON
// array of strings, since OIDC doesn't guarantee an array type across IdPs.
func normalizeGroups(value any) []string {
	switch v := value.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []any:
		groups := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				groups = append(groups, s)
			}
		}
		return groups
	default:
		return nil
	}
}
