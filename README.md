# SigNoz (local fork)

This is a local working fork of [SigNoz](https://github.com/SigNoz/signoz) with one
addition: native OpenID Connect (OIDC) login for the **Community Edition** binary,
independent of SigNoz's Enterprise license. See `plan.md` for the design and rationale.

What changed, at a glance:

- `pkg/authn/callbackauthn/oidccallbackauthn/` — new, clean-room generic OIDC
  `CallbackAuthN` provider (works against any OIDC-compliant IdP; Keycloak is the
  one it's been tested against).
- `pkg/signoz/authn.go` — wires the new provider into the Community binary's
  auth-provider map.
- `frontend/.../AuthDomain/CreateEdit/` — the "Add Domain" wizard no longer hides
  the OIDC option behind the Enterprise `sso` license feature flag (SAML still does,
  since no SAML provider is registered in Community).
- `cmd/community/Dockerfile.integration`, `tests/fixtures/signoz.py`,
  `tests/integration/tests/callbackauthn/06_community_oidc.py` — integration test
  infrastructure for the above, targeting the Community binary.
- `pkg/types/authtypes/domain.go`, `pkg/modules/session/implsession/module.go` — a
  wildcard (`*`) Auth Domain name, which any login falls back to when no
  domain-specific Auth Domain matches. SigNoz's Auth Domains are otherwise matched by
  exact email domain only (one IdP per verified corporate domain); this lets an IdP
  that already manages its own user directory (e.g. an existing Keycloak realm) be
  the sole access gate, regardless of what email domain a user has.

## Building the backend

The repo's `go.mod` pins Go 1.25.7. If your system's default Go toolchain is newer,
pin it explicitly or the build may fail on an unrelated dependency:

```bash
GOTOOLCHAIN=go1.25.7 GOARCH=amd64 GOOS=linux go build \
  -C cmd/community \
  -tags timetzdata \
  -o /home/felix/Dokumente/signoz/target/linux-amd64/signoz-community \
  -ldflags "-s -w -X github.com/SigNoz/signoz/pkg/version.variant=community"
```

Swap `GOARCH`/`GOOS` for your platform. Equivalent Makefile target (same build, plus
version ldflags): `make go-build-community`, output under `target/<os>-<arch>/`.

### Running it locally

`make go-run-community` runs the server directly via `go run`, with sane dev-env
defaults (SQLite metadata store, `SIGNOZ_WEB_ENABLED=false`). It expects a ClickHouse
instance reachable at `127.0.0.1:9000`:

```bash
docker run -d --name ch -p 9000:9000 -p 8123:8123 clickhouse/clickhouse-server
GOTOOLCHAIN=go1.25.7 make go-run-community
```

## Connecting to Keycloak

### 1. Create a client in Keycloak

In the Keycloak Admin Console, with your target realm selected:

1. **Clients → Create client.**
2. General settings: Client type `OpenID Connect`, Client ID `signoz` (or anything you
   like — you'll reuse it as `clientId` in SigNoz). Next.
3. Capability config: turn **Client authentication** on (confidential client).
   Leave **Standard flow** (authorization code) checked; the others aren't needed. Next.
4. Login settings:
   - **Valid redirect URIs**: `http://<signoz-host>:<port>/api/v1/complete/oidc`
     (this path is fixed, not configurable on the SigNoz side).
   - **Web origins**: can be left blank; discovery and token exchange happen
     server-to-server, not from the browser.
   Save.
5. Open the new client's **Credentials** tab and copy the **Client secret**.

Optional, if you want group-based role mapping in SigNoz:

6. **Client scopes → `signoz-dedicated` → Add mapper → By configuration → Group
   Membership.** Set *Token Claim Name* to `groups`, turn on **Add to ID token** (and
   **Add to userinfo** if you'll enable `getUserInfo` in SigNoz). Save.
7. **Groups → Create group** (e.g. `signoz-admins`), then **Users → <user> → Groups
   → Join Group** to put a test user in it.

Create or pick a test user under **Users**, and set a (non-temporary) password on
its **Credentials** tab. If you want `insecureSkipEmailVerified` to stay off in
SigNoz, make sure the user's email is marked verified (**Users → <user> → Email
verified** toggle).

### 2. Add the domain in SigNoz

1. Log in to SigNoz as an admin.
2. **Settings → Organization Settings → SSO → Add Domain.**
3. On "Configure Authentication Method", choose **OIDC Authentication → Configure**.
4. Fill in the form:
   - **Domain name**: the email domain of the users who should SSO through this,
     e.g. `yourcompany.com` — SigNoz matches on this at login time to decide whether
     to show password login or redirect to Keycloak. Use `*` instead to match *any*
     email domain with no exact-domain match — use this when Keycloak itself (its
     own realm's user directory) should be the only gate on who can log in, rather
     than restricting SSO to one corporate domain.
   - **Issuer**: `http://<keycloak-host>:<port>/realms/<realm>`.
   - **Issuer Alias**: leave blank unless SigNoz's backend and your browser resolve
     Keycloak via *different* hostnames (e.g. an internal Docker network name vs. a
     public one) — in that case, set **Issuer** to whichever URL the backend can
     reach for discovery, and **Issuer Alias** to the issuer string Keycloak's tokens
     actually carry.
   - **Client ID** / **Client Secret**: from step 1.
   - **Claim Mapping**: defaults (`email`, `name`, `groups`, `role`) match the
     standard Keycloak mapper names above — only change these if you used custom
     claim names.
   - **Insecure skip email verified** / **Get user info**: leave both off for a
     standard setup.
   - **Role Mapping**: set a **Default role** (e.g. `viewer`), and optionally a
     **Group → Role mapping** (e.g. `signoz-admins → admin`) if you set up the
     group mapper in step 1.
5. Toggle the domain **Enabled**, then **Save**.

### 3. Test it

Log out, go to the SigNoz login page, and enter an email at the domain you just
registered — it should redirect to Keycloak's login page instead of asking for a
password. After logging in there, you should land back in SigNoz, authenticated,
with the role your group/default mapping assigned.

### Alternative: via the API

The same thing can be done without the UI — `POST /api/v2/auth_domains` with a
`PostableAuthDomain` body (`{name, enabled, config: {kind: "oidc", spec: {...}},
roleMapping}`), using an admin bearer token from `/api/v2/sessions/email_password`.

## Building the frontend

Not yet wired into a reproducible build step in this fork — `pkg-signoz.nix` still
serves the upstream release's prebuilt `web/` assets. If you need the OIDC-visibility
fix reflected in a running deployment, build `frontend/` from source and point your
deployment's web directory at that output instead.

## NixOS deployment (`pkg-signoz.nix`)

The `signoz` package derivation in `pkg-signoz.nix` takes `web`/`templates`/`conf`
from the upstream release tarball but installs the locally built binary
(`../bin/signoz-community`, resolved relative to `pkg-signoz.nix`'s own directory) as
`bin/signoz`. Rebuilding the Go binary requires re-running your NixOS rebuild for the
change to take effect (Nix store inputs are hashed snapshots, not live references).

## Everything else

For the original project's documentation, install instructions, and feature overview,
see [signoz.io/docs](https://signoz.io/docs/) or the upstream repository at
[github.com/SigNoz/signoz](https://github.com/SigNoz/signoz).
