# Native OIDC (Keycloak) login for SigNoz Community Edition

## Goal

Let SigNoz Community log users in via any OIDC IdP (Keycloak in particular), natively,
with no reverse proxy in front and no Enterprise license. Clean-room: new code, not
copied from `ee/authn/callbackauthn/oidccallbackauthn` (not read for this task).

## Why this is structurally free of the license problem

Traced the full request path for an `oidc` Auth Domain under `cmd/community`:

- `pkg/apiserver/signozapiserver/session.go:117` already registers
  `GET /api/v1/complete/oidc` unconditionally, in both binaries.
- That handler (`pkg/modules/session/implsession/handler.go:106`) calls
  `module.CreateCallbackAuthNSession(ctx, authtypes.AuthNProviderOIDC, values)` —
  generic dispatch by provider key, not an ee-specific code path.
- Dispatch resolves `authtypes.AuthNProviderOIDC` against a
  `map[authtypes.AuthNProvider]authn.AuthN` (`pkg/modules/session/implsession/module.go`),
  which is built once at startup by `pkg/signoz/authn.go:NewAuthNs` — today, in
  `cmd/community/server.go`, that map only has `email_password` and `google`.
- Nothing in this chain (`pkg/apiserver`, `pkg/modules/session`, `pkg/signoz/authn.go`)
  references `licensing` in a gating way — the `licensing` param in `NewAuthNs` is
  accepted but unused. Today, configuring an `oidc` Auth Domain on community just 404s
  with "authn provider not found" because the map key is missing — not because of a
  license check.
- `pkg/types/authtypes/` (Auth Domain storage, `OIDCConfig`, claim/role mapping),
  `pkg/modules/authdomain/`, the relevant `pkg/sqlmigration/*` files, and
  `frontend/src/container/OrganizationSettings/AuthDomain/` are all root-MIT, not under
  `ee/`. The frontend SSO UI/button is driven purely by the session-context response
  (`authNSupport.callback`), not a license flag — it reflects whatever's in the map.

**Conclusion: the license gate lives entirely inside `ee/`'s own provider
implementation, self-contained.** Writing a new `authn.CallbackAuthN` implementation
under `pkg/` and adding one map entry in `cmd/community`'s wiring needs to satisfy no
license check anywhere in the shared call path. All the storage, config schema, admin
UI, and HTTP routing already exist and are reused as-is.

## What to build

One new package, modeled on the **interface contract** (`pkg/authn/authn.go`'s
`CallbackAuthN`) and the public APIs of `coreos/go-oidc` + `golang.org/x/oauth2`
(already a repo dependency) — using `pkg/authn/callbackauthn/googlecallbackauthn/` only
as a reference for "how does an existing non-ee provider satisfy this interface", not
as source to copy:

**`pkg/authn/callbackauthn/oidccallbackauthn/`** (new, generic — not Google-specific)

- `New(ctx, store authtypes.AuthNStore, providerSettings factory.ProviderSettings, globalConfig global.Config) (*AuthN, error)`
- `LoginURL`: discover the provider via `oidc.NewProvider(ctx, authDomain's configured Issuer)`
  (generic issuer from config, not hardcoded like Google's); build `oauth2.Config` with
  redirect path `/api/v1/complete/oidc`; return `AuthCodeURL`.
- `HandleCallback`: exchange code → verify ID token against the discovered provider →
  decode claims (see **Claim mapping — new logic** below) → honor
  `InsecureSkipEmailVerified` → optionally call the standard OIDC `userinfo` endpoint if
  `GetUserInfo` is set → return `authtypes.CallbackIdentity`.
- `ProviderInfo`: trivial passthrough, matches the interface (`RelayStatePath: nil`).
- Config accessor confirmed: `authDomain.Config().OIDCConfig()` already exists
  (`pkg/types/authtypes/domain_config.go:171`), mirrors `.GoogleConfig()` exactly. No
  surprises here — this part of the plan is now verified, not assumed.

### Claim mapping — new logic, not reuse (hole found)

Checked for an existing generic claim-extraction helper (`grep -rn "ClaimMapping"
pkg/`, `grep -rn "\.UserInfo(" pkg/`): **nothing consumes `AttributeMapping`/
`ClaimMapping` anywhere in `pkg/` today.** `googlecallbackauthn` doesn't use it either —
it decodes a fixed Google-specific claims struct (`name`, `email`, `email_verified`,
`hd`) and ignores `AttributeMapping` entirely. So the earlier draft's phrase "decode
claims per the Auth Domain's ClaimMapping" was describing desired behavior, not an
existing reusable path — this is new code to write:

1. Decode ID token (and, if `GetUserInfo` is set, the merged userinfo response) into a
   generic `map[string]any`, not a fixed struct.
2. Pull `email`/`name`/`groups`/`role` out by the key names in `ClaimMapping`
   (`AttributeMapping.Email/.Name/.Groups/.Role`), which already default to
   `"email"/"name"/"groups"/"role"` via `AttributeMapping.UnmarshalJSON` — reuse that
   defaulting, don't reimplement it.
3. Handle `groups` being absent, a single string, or a JSON array (OIDC claims don't
   guarantee array-typed group claims across IdPs) — normalize to `[]string`.
4. `GetUserInfo`: call `oidcProvider.UserInfo(ctx, oauth2.StaticTokenSource(token))`
   (public `go-oidc` API, no existing call site to model in this repo) and merge its
   claims over the ID token's before the mapping step above.

### Wiring — confirmed safe to extend the shared function

Add one entry to the map built in `pkg/signoz/authn.go:NewAuthNs` —
`authtypes.AuthNProviderOIDC: genericOIDCAuthN`. Checked whether this could collide with
the enterprise binary's own OIDC provider: `cmd/enterprise/server.go:128` calls
`signoz.NewAuthNs(...)` first (getting our generic entry too), then **unconditionally
overwrites** `authNs[authtypes.AuthNProviderOIDC]` and `[...AuthNProviderSAML]` with its
own `ee` implementations (lines 133-134). So extending the shared function cannot leak
into or conflict with the licensed enterprise behavior — enterprise always clobbers it
afterward. No need for an isolated community-only wiring function; extend
`pkg/signoz/authn.go` directly (also matches the existing one-function convention, no
duplication).

### HTTP layer — confirmed zero new code needed

Traced end to end: `pkg/apiserver/signozapiserver/session.go:117` already registers
`GET /api/v1/complete/oidc` unconditionally in both binaries →
`handler.CreateSessionByOIDCCallback` (`pkg/modules/session/implsession/handler.go:106`)
already calls `module.CreateCallbackAuthNSession(ctx, authtypes.AuthNProviderOIDC,
values)` generically → the session module's `getProvider[authn.CallbackAuthN]` map
lookup, role mapping (`RoleMapping.NewRolesFromCallbackIdentity`, the
`UseRoleAttribute` → `authz.GetByOrgIDAndName` check), and user auto-provisioning
(`userSetter.GetOrCreateUser`) are all already fully generic. The only missing piece in
the entire request path, confirmed by reading the code, is the map entry itself.

**No DB migration needed** — the `auth_domain` table and `OIDCConfig` schema already
support an `oidc` kind end-to-end; the admin UI (`CreateEdit/Providers/AuthnOIDC.tsx`)
already renders OIDC config forms unconditionally.

## Test infrastructure gap (hole found)

Checked whether the existing Keycloak-based integration test fixtures could just be
pointed at the new provider: **they can't, yet.** `tests/fixtures/signoz.py:51-53`
hardcodes building `cmd/enterprise/Dockerfile.integration` (or the `.with-web` variant)
for every integration test — there is no `cmd/community/Dockerfile.integration` at all.
So "add an integration test targeting the community binary" is not just a new test
file; it first needs:

- A new `cmd/community/Dockerfile.integration` (can mirror the enterprise one's
  structure, pointed at `cmd/community`).
- A way for `tests/fixtures/signoz.py`'s `create_signoz` (or a new community-specific
  fixture) to select which binary/image gets built, rather than hardcoding enterprise.

Decide up front whether this test infrastructure work is in scope for v1, or whether
initial verification stays manual (step 6 below) with automated coverage as a
follow-up.

## Implementation steps

1. Read `docs/contributing/go/` conventions before writing; follow existing patterns
   (`googlecallbackauthn` for interface shape, `emailpasswordauthn` for package layout).
2. Implement `pkg/authn/callbackauthn/oidccallbackauthn/authn.go` against the
   `CallbackAuthN` interface, using `coreos/go-oidc/v3/oidc` + `golang.org/x/oauth2`,
   including the new claim-mapping/userinfo logic above (no existing helper to reuse).
3. Add the map entry in `pkg/signoz/authn.go:NewAuthNs`.
4. `gofmt`; run `make gen-openapi-specs` only if any API contract/type actually changed
   (not expected, since the route and config schema are reused as-is) — keep that as
   its own commit if needed, per repo convention.
5. Manually verify: build `cmd/community`, configure an Auth Domain (kind `oidc`)
   against a real Keycloak realm via the existing admin UI, confirm login redirect →
   Keycloak → callback → session issued, including a group→role mapping case.
6. Decide on the test-infrastructure gap above; if in scope, add the community
   Dockerfile + fixture support, then an integration test under
   `tests/integration/tests/callbackauthn/` reusing `tests/fixtures/idp.py` /
   `tests/fixtures/keycloak.py` as the IdP — written fresh against the new provider,
   not copied from the existing ee OIDC test file.

## Open items

- Group/role claim naming convention to document for Keycloak admins — which Keycloak
  client scope/mapper produces the `groups` claim consumed by `RoleMapping`, and how to
  configure a custom `role` claim for `UseRoleAttribute`.
- Whether the community Dockerfile/fixture work (test infrastructure gap) lands in this
  change or as a fast-follow with manual verification in the meantime.
