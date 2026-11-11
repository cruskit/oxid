# oxID

An OpenID Provider written in Rust, implementing:

- the [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
- the [ConnectID FAPI 2.0 Security Profile](https://cdn.connectid.com.au/specifications/connectid-fapi-security-profile-03.html)

All OAuth 2.0 and OpenID Connect logic lives in this repository; no third-party
OIDC library is used. Cryptography is never implemented here: TLS comes from
`rustls`, JWS signing and verification from `jsonwebtoken`, hashing and random
numbers from `aws-lc-rs`, and password hashing from `argon2`.

## What it implements

| Area | Behaviour |
| --- | --- |
| Flow | Authorization code only, via pushed authorization requests (RFC 9126). Requests that do not come through PAR are rejected. |
| Request objects | Mandatory, signed with PS256 (RFC 9101). `nbf` at most 10 minutes old, `exp` at most 10 minutes after `nbf`. Parameters outside the request object are ignored. |
| Client authentication | `private_key_jwt` with PS256. The audience must be the issuer identifier as a single string. Assertions cannot be replayed. |
| PKCE | Required, `S256` only. |
| Access tokens | Opaque, bound to the client's TLS certificate (RFC 8705), valid for at most 10 minutes. |
| Refresh tokens | Optional per client, not rotated. |
| ID tokens | PS256, pairwise `sub`, always carry `txn`. |
| Claims | The `claims` request parameter, standard identity claims, and `verified_claims` under the `au_connectid` trust framework (`over16` to `over65`). |
| Authorization response | Query mode, with the `iss` parameter (RFC 9207), sent with a 303 redirect. |
| Discovery | OpenID Connect Discovery and RFC 8414 metadata, including `mtls_endpoint_aliases`. |
| Transport | TLS 1.2 and 1.3 only, BCP 195 cipher suites, HSTS. |
| Headers | `x-fapi-interaction-id` is echoed, or generated, on every response and logged. |

### Endpoints

Two TLS listeners serve the same routes. The public listener never asks for a
client certificate, so browsers are not prompted. The mTLS listener requests
one and is advertised through `mtls_endpoint_aliases`.

| Path | Purpose |
| --- | --- |
| `/.well-known/openid-configuration` | Provider metadata (also at `/.well-known/oauth-authorization-server`) |
| `/jwks` | The provider's public signing keys |
| `/par` | Pushed authorization request endpoint |
| `/authorize` | Authorization endpoint: sign-in and consent page |
| `/token` | Token endpoint |
| `/userinfo` | UserInfo endpoint |
| `/healthz` | Liveness check |

## Current limitations

This is an initial version. By design it does not yet have:

- **User registration.** Users are a static list in the configuration file. If
  none are configured, a single built-in demo user is used (`demo` /
  `demo-password`); oxID logs a warning when it does this. Do not expose an
  instance running with the demo user.
- **Client registration.** Clients are a static list in the configuration file.
- **Persistence.** Pushed requests, codes and tokens are held in memory, so they
  are lost on restart and a deployment is a single instance.
- **Sessions.** Every authorization asks the user to sign in.

Users and clients sit behind the `UserStore` and `ClientRegistry` traits, which
is where registration and a database will plug in.

## Getting started

The toolchain is pinned with [mise](https://mise.jdx.dev/):

```sh
mise install          # installs the Rust toolchain
mise run check        # format check, clippy, unit and integration tests
```

To run a local instance:

```sh
cp oxid.example.toml oxid.toml   # then edit it
cargo run -- serve --config oxid.toml
```

With no TLS certificate, signing key or pairwise salt configured, oxID
generates ephemeral ones at startup and says so in the log. That is convenient
for development and wrong for anything else.

To create a password hash for a configured user:

```sh
echo 'the-password' | cargo run -- hash-password
```

## Configuration

See [`oxid.example.toml`](oxid.example.toml) for every option. Lifetimes are
validated at startup against the limits the profiles set, so a configuration
that would break compliance (for example a 20 minute access token) is refused.

## Testing

| Command | What it runs |
| --- | --- |
| `mise run test` | Unit tests for each component, and integration tests that start a real oxID instance on ephemeral ports and drive it over TLS and mutual TLS. |
| `mise run conformance` | The OpenID Foundation conformance suite. |
| `mise run build` | Everything: format, lint, tests, release build, then the conformance suite. |

### Conformance suite

`scripts/conformance.sh` runs the
[OpenID Foundation conformance suite](https://openid.net/certification/about-conformance-suite/)
against oxID. It needs Docker, Python 3 and git. It:

1. builds oxID into a container image (`Dockerfile`);
2. starts it beside the suite's prebuilt images (`conformance/docker-compose.yml`);
3. generates throwaway client keys and the suite configuration
   (`conformance/generate.py`);
4. drives the suite's own `run-test-plan.py` with this plan:

   ```
   fapi2-message-signing-final-test-plan
     [openid=openid_connect][client_auth_type=private_key_jwt]
     [fapi_request_method=signed_non_repudiation][sender_constrain=mtls]
     [fapi_profile=connectid_au][fapi_response_mode=plain_response]
   ```

5. stops the containers, leaving logs and exported results in
   `conformance/results/`.

The suite's browser automation signs in as the demo user. Nothing is published
beyond loopback: the suite UI is on `https://localhost:8943/` and oxID on
`https://localhost:9443/`.

Useful settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SUITE_TAG` | `release-v5.3.4` | Suite release, used for both the images and `run-test-plan.py` |
| `SUITE_HOST_PORT` | `8943` | Loopback port for the suite UI and API |
| `OXID_HOST_PORT` | `9443` | Loopback port for oxID's public listener |
| `KEEP_RUNNING` | `0` | Set to `1` to leave the containers up so results can be browsed |

Results the suite is expected to report as failures or skips, if any, are
recorded with their reasons in `conformance/expected-failures.json` and
`conformance/expected-skips.json`.

## Layout

```
src/
  main.rs            command line
  server.rs          TLS listeners, connection handling, shutdown
  tls.rs             TLS versions, cipher suites, client certificate policy
  config.rs          configuration file and its validation
  state.rs           shared application state
  http/              routing, endpoints, shared extractors and headers
  authz.rs           authorization request parameters and their rules
  request_object.rs  signed request object verification
  client_auth.rs     private_key_jwt client authentication
  jose.rs            compact JWS framing and key selection
  keys.rs            the provider's signing key and JWK Set
  pkce.rs            PKCE (S256)
  claims.rs          claims parameter, claim release, verified_claims
  id_token.rs        ID token and UserInfo claim assembly
  subject.rs         pairwise subject identifiers
  client.rs          clients and the ClientRegistry trait
  user.rs            users and the UserStore trait
  store.rs           in-memory requests, codes, tokens, replay cache
tests/               integration tests against a running instance
conformance/         conformance suite configuration
scripts/             conformance runner
```
