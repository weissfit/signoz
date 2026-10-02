package oidccallbackauthn

import (
	"context"
	"log/slog"
	"net/url"
	"path"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/SigNoz/signoz/pkg/authn"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/global"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

const redirectPath string = "/api/v1/complete/oidc"

var scopes []string = []string{oidc.ScopeOpenID, "email", "profile"}

var _ authn.CallbackAuthN = (*AuthN)(nil)

type AuthN struct {
	store        authtypes.AuthNStore
	settings     factory.ScopedProviderSettings
	globalConfig global.Config
}

func New(ctx context.Context, store authtypes.AuthNStore, providerSettings factory.ProviderSettings, globalConfig global.Config) (*AuthN, error) {
	settings := factory.NewScopedProviderSettings(providerSettings, "github.com/SigNoz/signoz/pkg/authn/callbackauthn/oidccallbackauthn")

	return &AuthN{
		store:        store,
		settings:     settings,
		globalConfig: globalConfig,
	}, nil
}

func (a *AuthN) LoginURL(ctx context.Context, siteURL *url.URL, authDomain *authtypes.AuthDomain) (string, error) {
	oidcConfig, err := authDomain.Config().OIDCConfig()
	if err != nil {
		return "", err
	}

	oidcProvider, err := a.discoverProvider(ctx, oidcConfig)
	if err != nil {
		return "", err
	}

	oauth2Config := a.oauth2Config(siteURL, oidcConfig, oidcProvider)

	return oauth2Config.AuthCodeURL(authtypes.NewState(siteURL, authDomain.StorableAuthDomain().ID).URL.String()), nil
}

func (a *AuthN) HandleCallback(ctx context.Context, query url.Values) (*authtypes.CallbackIdentity, error) {
	if errMsg := query.Get("error"); errMsg != "" {
		a.settings.Logger().ErrorContext(ctx, "oidc: error while authenticating", slog.String("error", errMsg), slog.String("error_description", query.Get("error_description")))
		return nil, errors.Newf(errors.TypeInternal, errors.CodeInternal, "oidc: error while authenticating").WithAdditional(query.Get("error_description"))
	}

	state, err := authtypes.NewStateFromString(query.Get("state"))
	if err != nil {
		a.settings.Logger().ErrorContext(ctx, "oidc: invalid state", errors.Attr(err))
		return nil, errors.Newf(errors.TypeInvalidInput, authtypes.ErrCodeInvalidState, "oidc: invalid state").WithAdditional(err.Error())
	}

	authDomain, err := a.store.GetAuthDomainFromID(ctx, state.DomainID)
	if err != nil {
		return nil, err
	}

	oidcConfig, err := authDomain.Config().OIDCConfig()
	if err != nil {
		return nil, err
	}

	oidcProvider, err := a.discoverProvider(ctx, oidcConfig)
	if err != nil {
		return nil, err
	}

	oauth2Config := a.oauth2Config(state.URL, oidcConfig, oidcProvider)

	token, err := oauth2Config.Exchange(ctx, query.Get("code"))
	if err != nil {
		var retrieveError *oauth2.RetrieveError
		if errors.As(err, &retrieveError) {
			a.settings.Logger().ErrorContext(ctx, "oidc: failed to get token", errors.Attr(err), slog.String("error_description", retrieveError.ErrorDescription), slog.String("body", string(retrieveError.Body)))
			return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: failed to get token").WithAdditional(retrieveError.ErrorDescription)
		}

		a.settings.Logger().ErrorContext(ctx, "oidc: failed to get token", errors.Attr(err))
		return nil, errors.Newf(errors.TypeInternal, errors.CodeInternal, "oidc: failed to get token")
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New(errors.TypeInvalidInput, errors.CodeInvalidInput, "oidc: no id_token in token response")
	}

	verifier := oidcProvider.Verifier(&oidc.Config{ClientID: oidcConfig.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		a.settings.Logger().ErrorContext(ctx, "oidc: failed to verify token", errors.Attr(err))
		return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: failed to verify token")
	}

	claims := make(map[string]any)
	if err := idToken.Claims(&claims); err != nil {
		a.settings.Logger().ErrorContext(ctx, "oidc: missing or invalid claims", errors.Attr(err))
		return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: missing or invalid claims").WithAdditional(err.Error())
	}

	if oidcConfig.GetUserInfo {
		userInfo, err := oidcProvider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			a.settings.Logger().ErrorContext(ctx, "oidc: failed to fetch userinfo", errors.Attr(err))
			return nil, errors.Newf(errors.TypeInternal, errors.CodeInternal, "oidc: failed to fetch userinfo")
		}

		if userInfo.Subject != idToken.Subject {
			a.settings.Logger().ErrorContext(ctx, "oidc: userinfo subject does not match id token subject")
			return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: userinfo subject does not match id token subject")
		}

		userInfoClaims := make(map[string]any)
		if err := userInfo.Claims(&userInfoClaims); err != nil {
			a.settings.Logger().ErrorContext(ctx, "oidc: missing or invalid userinfo claims", errors.Attr(err))
			return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: missing or invalid userinfo claims").WithAdditional(err.Error())
		}

		claims = mergeClaims(claims, userInfoClaims, oidcConfig.ClaimMapping.Email)
	}

	if !isEmailVerified(claims, oidcConfig.InsecureSkipEmailVerified) {
		a.settings.Logger().ErrorContext(ctx, "oidc: email is not verified")
		return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "oidc: email is not verified")
	}

	name, rawEmail, groups, role := mapIdentity(claims, oidcConfig.ClaimMapping)

	email, err := valuer.NewEmail(rawEmail)
	if err != nil {
		return nil, errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "oidc: failed to parse email").WithAdditional(err.Error())
	}

	return authtypes.NewCallbackIdentity(name, email, authDomain.StorableAuthDomain().OrgID, state, groups, role), nil
}

func (a *AuthN) ProviderInfo(ctx context.Context, authDomain *authtypes.AuthDomain) *authtypes.AuthNProviderInfo {
	return &authtypes.AuthNProviderInfo{
		RelayStatePath: nil,
	}
}

// discoverProvider runs OIDC discovery against the configured issuer. When IssuerAlias is
// set, the discovery document's issuer claim is expected to differ from the discovery URL
// (e.g. an internal vs. external hostname), so the alias is substituted for issuer
// validation.
func (a *AuthN) discoverProvider(ctx context.Context, oidcConfig authtypes.OIDCConfig) (*oidc.Provider, error) {
	if oidcConfig.IssuerAlias != "" {
		ctx = oidc.InsecureIssuerURLContext(ctx, oidcConfig.IssuerAlias)
	}

	return oidc.NewProvider(ctx, oidcConfig.Issuer)
}

func (a *AuthN) oauth2Config(siteURL *url.URL, oidcConfig authtypes.OIDCConfig, provider *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     oidcConfig.ClientID,
		ClientSecret: oidcConfig.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
		RedirectURL: (&url.URL{
			Scheme: siteURL.Scheme,
			Host:   siteURL.Host,
			Path:   path.Join(a.globalConfig.ExternalPath(), redirectPath),
		}).String(),
	}
}
