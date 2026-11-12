# oxID

An OpenID Provider written in Rust, implementing:

- the [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
- the [ConnectID FAPI 2.0 Security Profile](https://cdn.connectid.com.au/specifications/connectid-fapi-security-profile-03.html)
- the [ConnectID Identity Assurance Profile](https://cdn.connectid.com.au/specifications/connectid-identity-assurance-profile-08.html)
- the [OAuth 2 Purpose request parameter](https://cdn.connectid.com.au/specifications/oauth2-purpose-01.html)

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
| ID tokens | PS256, pairwise `sub`, always carry `txn`, never carry `acr`. |
| Claims | Set per client by its profile: the ConnectID identity assurance claims, or every standard OpenID Connect claim; see [Claims](#claims). |
| User experience | Pluggable: the interaction at the authorization endpoint is a module chosen in configuration; see [User experience modules](#user-experience-modules). |
| Consent | In the `login` experience, the user chooses which voluntary claims to share. Essential claims can only be refused by cancelling; see [Consent](#consent). |
| Purpose | The `purpose` parameter is validated, shown to the user at consent, and recorded with the transaction; see [Purpose](#purpose). |
| Authorization response | Query mode, with the `iss` parameter (RFC 9207), sent with a 303 redirect. |
| Discovery | OpenID Connect Discovery and RFC 8414 metadata, including `mtls_endpoint_aliases`. |
| Transport | TLS 1.2 and 1.3 only, BCP 195 cipher suites, HSTS. |
| Headers | `x-fapi-interaction-id` is echoed, or generated, on every response and logged. |

### Claims

Each client has a `profile` that decides which claims exist for it. The
security profile (FAPI 2.0 with the ConnectID restrictions) is the same for
every client.

| Profile | Claims | Requested with |
| --- | --- | --- |
| `connectid` (default) | Exactly those of the ConnectID Identity Assurance Profile, below. | The `claims` parameter only. Claim scopes imply nothing. |
| `oidc` | Every standard claim of OpenID Connect Core §5.1: `name`, `given_name`, `family_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `email`, `email_verified`, `gender`, `birthdate`, `zoneinfo`, `locale`, `phone_number`, `phone_number_verified`, `address`, `updated_at`. No verified claims. | The `claims` parameter, or the `profile`, `email`, `phone` and `address` scopes (delivered from UserInfo). |

The ConnectID claims:

| Kind | Claims |
| --- | --- |
| Standard | `given_name`, `middle_name`, `family_name`, `email`, `birthdate`, `phone_number`, `address` (`street_address`, `locality`, `region`, `postal_code`, `country`), `txn` |
| Verified: age | `over16`, `over18`, `over21`, `over25`, `over65`, derived from `birthdate` |
| Verified: bank account | `beneficiary_account_au` (BSB and account number), `beneficiary_account_au_payid` (PayID, falling back to BSB and account number), `beneficiary_account_international` (BIC, account number, one-line address) |

- Verified claims are released only when the request names the `au_connectid`
  trust framework, as `{"trust_framework": {"value": "au_connectid"}}`. A
  request whose trust framework is absent, null, malformed or different is
  ignored, and the response always carries `"trust_framework": "au_connectid"`.
- A client can be narrowed further, to the claims it is provisioned for, with
  `claims` in its configuration. Requests for claims outside the client's
  profile or provisioning are ignored rather than rejected.
- A requested claim the user does not have is left out without an error, even
  when it was requested as essential.
- `txn` is in every ID token whether requested or not.
- A user reaches each age at 00:00 UTC on their birthday.
- Discovery is one document for the whole server. It advertises the claims
  and scopes of the profiles that registered clients actually use, so a
  server with only `connectid` clients advertises exactly the ConnectID
  claims, as that profile requires. Registering an `oidc` client adds the
  remaining standard claims and the claim scopes.

### User experience modules

What the user sees at the authorization endpoint is a module, selected with
`experience` in the configuration file (or `--experience` /
`OXID_EXPERIENCE`, which override it). The protocol work around it is shared:
finding the pushed request, CSRF protection, single use of the `request_uri`,
issuing the code, recording the transaction and building the redirect.

| Module | For | What it does |
| --- | --- | --- |
| `technical` (default) | Development, debugging, testing relying parties | No sign-in. Shows the request, lets you pick a customer and an outcome, and lets you edit the ID token claims before they are issued. |
| `login` | The basis for a real end-user flow | Username and password sign-in with per-claim consent, described under [Consent](#consent). |

> The `technical` module has no authentication: anyone who can reach the
> authorization endpoint can act as any customer and change what is asserted
> about them. oxID logs a warning when it starts with it. Never expose it to
> real users.

The `technical` module is a single page:

- **Request**, on one side. The request's parameters, and the request object
  decoded (header and payload) with the original encoded JWT one click away.
- **Response**, on the other.
  - *Customer.* One of the predefined customers, whose attributes can be
    expanded. The customer used on the last completed flow is preselected
    (remembered in a cookie).
  - *Outcome.* Success or error.
  - *Success.* The ID token payload as JSON, before signing, free to edit:
    change, add or remove any claim, including protocol claims such as `iss`
    or `exp`. Choosing another customer swaps in that customer's claims, the
    JSON is checked as you type, and Reset returns to the generated claims.
  - *Error.* One of the predefined errors (`access_denied`, `login_required`,
    `consent_required`, `interaction_required`,
    `account_selection_required`, `invalid_request`, `invalid_scope`,
    `unauthorized_client`, `server_error`, `temporarily_unavailable`) with an
    editable `error_description`.
  - *Send.* A preview of the redirect, and one button.

The page is a plain HTML form improved by a small script, which runs under a
per-response Content Security Policy nonce. Without the script it still works:
if a different customer is submitted than the claims were generated for, the
page comes back with that customer's claims instead of sending a mismatch.

Edits are stored as differences from what was shown. Claims you leave alone
get their real values when the token is issued: `iat`, `exp` and `auth_time`
are set at that moment and `at_hash` is computed from the access token. The
token is always properly signed. Edits apply to the ID token, not to UserInfo.

The customers are the configured `users`, or four built-in ones when none are
configured: `demo` (an adult with every claim), `riley` (under 18), `margaret`
(over 65) and `sam` (sparse details). A configured user needs a
`password_hash` only to sign in under `login`.

To add a module, implement the `Experience` trait in `src/experience/`, add a
variant to `experience::Kind`, and construct it in `experience::build`.

### Consent

This describes the `login` module. The sign-in page lists every claim that would be released. Claims requested
with `"essential": true` are marked as required and have no checkbox; the only
way to refuse them is to cancel the request. Every other claim, including those
implied by a scope, has a checkbox that starts ticked, and the user can untick
any of them before continuing.

The choice is stored with the grant, so a declined claim is left out of the ID
token, of UserInfo, and of tokens issued later by refresh. The client receives
no error for a declined claim; it is simply absent.

### Purpose

`purpose` must be 3 to 300 characters and free of control characters. A
request that breaks this fails with `error=invalid_request` and
`error_description=invalid_purpose`. Because requests arrive only through PAR,
the client receives that error from the PAR endpoint.

The purpose is shown, HTML-escaped, on the sign-in and consent page. Each
decided transaction is recorded with its `txn`, client, user, purpose, the
claims shared, the claims declined and the outcome, and is written to the log. The records are
held in memory (the most recent 10,000) and there is no consent history page
for users yet.

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

### Clients from the ConnectID registry

Clients can be listed in the configuration file, loaded from the ConnectID
registry, or both. Registry loading follows the
[ConnectID Client Registration](https://cdn.connectid.com.au/specifications/digitalid-client-registration-05.html)
profile and is off unless `[client_sync]` is present with `enabled = true`.

At startup, before any request is served, oxID:

1. reads the registry's metadata and takes the token endpoint from
   `mtls_endpoint_aliases`;
2. obtains an access token with the client credentials grant, authenticating
   with `private_key_jwt` (PS256, with the configured key id) over mutual TLS
   with the configured transport certificate;
3. calls the clients endpoint with that token over mutual TLS, reading every
   page;
4. registers each active client, fetching its keys from its `jwks_uri`. The
   client's `claims` and `claims_in_verified_claims` become the claims it is
   provisioned for.

Registry clients are added to the configured ones; if a client id is in both,
the configured definition is used. If the registry cannot be reached or
refuses the request, oxID does not start. An individual entry that is
inactive, malformed or whose keys cannot be fetched is logged and skipped.

Pagination follows the registry's API definition. Pages are requested with
`page` (zero-indexed) and `size` (`page_size`, default 50, the registry's own
default). Each response carries the clients in `content` beside `totalPages`,
`totalSize` and `pageNumber`, and pages are read until `totalPages` have been
fetched. A response that is not in that form, or that reports a different page
than was asked for, stops the synchronisation. Only clients whose `status` is
`Active` are registered.

Not done yet: periodic refresh of the client list and of each client's keys,
which the profile requires of a production identity provider; fetching
`sector_identifier_uri` to check the redirect URIs (its host is used as the
sector identifier); and verifying software statements.

## Current limitations

This is an initial version. By design it does not yet have:

- **User registration.** Users are a static list in the configuration file. If
  none are configured, four built-in demo customers are used (`demo`, `riley`,
  `margaret` and `sam`, all with the password `demo-password`); oxID logs a
  warning when it does this. Do not expose an instance running with them.
- **Other experience modules.** Presenting verifiable credentials, and
  self-registration, are planned as further modules and are not built.
- **Client registration.** Clients come from the configuration file and,
  optionally, the ConnectID registry at startup. There is no dynamic
  registration and no refresh while running.
- **Users and clients in a database.** Server-side state can be kept in
  DynamoDB (see [State and AWS Lambda](#state-and-aws-lambda)), but users and
  clients are still loaded from the configuration at startup.
- **Sessions.** Every authorization asks the user to sign in. For the same
  reason there is no page where a user can review their consent history,
  although the records are kept.

Users and clients sit behind the `UserStore` and `ClientRegistry` traits, which
is where registration and a database will plug in.

## State and AWS Lambda

Pushed requests, authorization codes, tokens, the client assertion replay
cache and consent records are kept in a store with two backends, chosen in
`[store]`:

| `backend` | Where | Use |
| --- | --- | --- |
| `memory` (default) | This process. Lost on restart, not shared. | A single local instance. |
| `dynamodb` | An Amazon DynamoDB table. | Several instances, or AWS Lambda, where consecutive requests may reach different instances. |

Both go through the same rules for expiry, single use and replay detection,
and the same tests run against each (the DynamoDB ones against DynamoDB
Local). With `dynamodb`, the signing key and pairwise salt are generated once
and kept in the table unless they are configured, so that every instance
issues tokens under the same key.

DynamoDB and Lambda support is behind the `aws` cargo feature, which the
default build leaves out:

```sh
cargo build --release --features aws    # oxid with the DynamoDB store, and oxid-lambda
mise run lambda                         # dist/lambda/oxid-lambda.zip, built on Amazon Linux 2023
```

`oxid-lambda` serves the same endpoints from a Lambda function behind an API
Gateway HTTP API. API Gateway terminates TLS; oxID takes the caller's client
certificate from the request context that API Gateway sets on a custom domain
name with mutual TLS enabled.

What the function needs from AWS (the table's key schema and TTL attribute,
the IAM actions, the runtime) is recorded in
[`deploy/aws/requirements.json`](deploy/aws/requirements.json) and published
with each release, so infrastructure code can be written against a release
rather than against this source tree. See
[`deploy/aws/README.md`](deploy/aws/README.md).

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
| `mise run test` | Unit tests for each component, and integration tests that start a real oxID instance on ephemeral ports and drive it over TLS and mutual TLS. Set `OXID_TEST_DYNAMODB_ENDPOINT` to the URL of a DynamoDB Local instance to include the DynamoDB store. |
| `mise run conformance` | The OpenID Foundation conformance suite. |
| `mise run build` | Everything: format, lint, tests, release build, then the conformance suite. |

### Continuous integration and releases

`.github/workflows/build.yml` runs on GitHub-hosted runners for every push to
`main` and every pull request. It checks formatting, lints, runs the unit and
integration tests (with DynamoDB Local for the DynamoDB store), builds the
Lambda package, and runs the conformance suite once per user experience
module, in parallel jobs, whose results are kept as the
`conformance-results-<experience>` artifacts.

Releases are made on demand:

1. Set the new version in `Cargo.toml` and merge it to `main`.
2. In GitHub, open **Actions > Build > Run workflow**, choose `main`, and tick
   **Create a GitHub release**.

Once the checks and the conformance suite pass, the workflow tags the commit
`v<version>` and publishes a release. It refuses to run if that version was
already released. The release has, each with a SHA-256 checksum:

| Asset | Contents |
| --- | --- |
| `oxid-v<version>-x86_64-unknown-linux-gnu.tar.gz` | The `oxid` server binary, this README, the example configuration and `deploy/`. |
| `oxid-lambda-v<version>-x86_64.zip` | The AWS Lambda deployment package. |
| `oxid-aws-requirements-v<version>.json` | What that package needs from AWS. |

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
   `conformance/results/<experience>/`.

The whole plan is run once for each user experience module. A module decides
who the response is about and what goes into the tokens, so a module can break
conformance on its own, and the plan takes about two minutes. Each module has
its own browser automation in `conformance/generate.py`: for `technical` the
suite goes through the response preview page and sends it unedited; for
`login` it signs in as the demo user. A new module needs an entry there and in
the `EXPERIENCES` list in `scripts/conformance.sh` and the workflow matrix.

Nothing is published
beyond loopback: the suite UI is on `https://localhost:8943/` and oxID on
`https://localhost:9443/`.

Useful settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SUITE_TAG` | `release-v5.3.4` | Suite release, used for both the images and `run-test-plan.py` |
| `SUITE_HOST_PORT` | `8943` | Loopback port for the suite UI and API |
| `OXID_HOST_PORT` | `9443` | Loopback port for oxID's public listener |
| `OXID_EXPERIENCE` | unset | Run for one module only (`technical` or `login`); unset runs each in turn |
| `KEEP_RUNNING` | `0` | Set to `1` to leave the containers up so results can be browsed (use with `OXID_EXPERIENCE`) |

Results the suite is expected to report as failures or skips, if any, are
recorded with their reasons in `conformance/expected-failures.json` and
`conformance/expected-skips.json`.

## Layout

```
src/
  main.rs            command line
  bin/oxid-lambda.rs the AWS Lambda entry point (feature `aws`)
  lambda.rs          serving API Gateway events (feature `aws`)
  server.rs          TLS listeners, connection handling, shutdown
  tls.rs             TLS versions, cipher suites, client certificate policy
  config.rs          configuration file and its validation
  state.rs           shared application state
  http/              routing, endpoints, shared extractors and headers
  experience/        pluggable user experiences: technical, login
  authz.rs           authorization request parameters and their rules
  request_object.rs  signed request object verification
  client_auth.rs     private_key_jwt client authentication
  client_sync.rs     loading clients from the ConnectID registry
  jose.rs            compact JWS framing and key selection
  keys.rs            the provider's signing key and JWK Set
  pkce.rs            PKCE (S256)
  claims.rs          claims parameter, claim release, verified_claims
  id_token.rs        ID token and UserInfo claim assembly
  subject.rs         pairwise subject identifiers
  client.rs          clients and the ClientRegistry trait
  user.rs            users and the UserStore trait
  store/             requests, codes, tokens, replay cache, consent records;
                     memory and DynamoDB backends
tests/               integration tests against a running instance
conformance/         conformance suite configuration
deploy/aws/          what a deployment on AWS Lambda needs
scripts/             conformance runner, Lambda package build
```
