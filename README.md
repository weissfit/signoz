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

1. In your Keycloak realm, create a confidential client. Set its valid redirect URI
   to `http://<signoz-host>:<port>/api/v1/complete/oidc` (fixed path, not configurable).
2. Note the realm issuer (`http://<keycloak-host>/realms/<realm>`) and the client
   secret.
3. In SigNoz, log in as an admin and go to Organization Settings → SSO → Add Domain →
   OIDC Authentication, and fill in the issuer/client id/secret. The domain name you
   register must match the email domain of the users who should SSO through it.
   - If SigNoz and Keycloak don't agree on Keycloak's hostname (e.g. an internal vs.
     externally-visible URL), set `issuer` to whichever URL SigNoz's backend can reach
     for discovery, and `issuerAlias` to the issuer string Keycloak's tokens actually
     carry.
4. Alternatively, configure the domain directly via the API —
   `POST /api/v2/auth_domains` with a `PostableAuthDomain` body
   (`{name, enabled, config: {kind: "oidc", spec: {...}}, roleMapping}`).

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
