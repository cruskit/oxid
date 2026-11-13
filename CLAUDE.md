# oxID

An OpenID Provider in Rust that implements the **FAPI 2.0 Security Profile**
(Message Signing) and the **ConnectID (Australia) FAPI 2.0 Security Profile**.
It must keep passing the OpenID Foundation conformance suite. The user-facing
overview is in `README.md`, and the AWS deployment contract is in
`deploy/aws/README.md`.

The deployment lives in a separate private repository,
`cruskit/oxid-infra` (checked out at `../oxid-infra`). It pins an oxID
release and deploys it to AWS Lambda.

## Ground rules from the owner

- **Write the OpenID Connect / OAuth logic in this crate.** Do not add a
  third-party OIDC or OAuth library.
- **Never write cryptography yourself.** Signing, verification, hashing, TLS
  and key handling go through established crates: `aws-lc-rs`,
  `jsonwebtoken` (aws_lc_rs backend), `rustls`, `rcgen` and `argon2`.
- **Do not build the verifiable credentials (VC) experience module.** It is
  planned, but out of scope.
- When the spec leaves a choice open, take the stricter FAPI 2.0 / ConnectID
  reading, and cite the clause in a doc comment (for example
  `ConnectID §4.2-3.4` or `RFC 9126`), as the existing code does.

## Commands

The Rust toolchain comes from mise. Use `mise exec -- cargo …`, or a task:

```sh
mise run check        # fmt + clippy (default and `aws` features) + tests
mise run test         # cargo test --locked --features aws
mise run lambda       # Lambda package into dist/lambda (Docker)
mise run conformance  # OIDF conformance suite in Docker (slow: ~minutes per experience)
mise run build        # check + release build + conformance
```

- On this machine, pass `-j 3` to cargo to limit build parallelism.
- Clippy runs with `pedantic` and `-D warnings`. `unsafe_code` is forbidden.
  Add product names to `clippy.toml` `doc-valid-idents`, not to backticks.
- The DynamoDB store tests run only when `OXID_TEST_DYNAMODB_ENDPOINT` is set
  (for example DynamoDB Local on `http://localhost:8000`). CI sets it.
- `scripts/conformance.sh` runs each experience in turn. Set
  `OXID_EXPERIENCE=technical|login` to run just one, and `KEEP_RUNNING=1` to
  browse the results. The suite version is in `SUITE_TAG`. Expected
  failures and skips are in `conformance/expected-*.json`. A change that
  adds a failure is a regression, unless the failure is justified and added
  there.
- Bind test listeners to loopback only. An unrelated `unifi` container
  already holds host ports 8080 and 8443. The conformance runner uses
  8943 (suite) and 9443 (oxID).

## Architecture

- `src/lib.rs` re-exports the crate. `main.rs` is the CLI. `server.rs` and
  `tls.rs` set up the two TLS listeners: public, and mTLS for the token, PAR
  and UserInfo endpoints.
- `src/http/` holds the endpoints: discovery/JWKS, PAR, authorize, token and
  UserInfo. The protocol rules sit in `authz.rs`, `request_object.rs` (JAR),
  `client_auth.rs` (private_key_jwt only), `pkce.rs` (S256 only),
  `claims.rs` (the claims parameter, `verified_claims`, release decisions),
  `id_token.rs` and `subject.rs` (pairwise subjects).
- `src/experience/` holds the pluggable UI at the authorization endpoint (the
  `Experience` trait, a state machine over HTML forms):
  - `login`: the end-user demonstration, branded as oxID. A login page
    (which shows nothing about the request), then a consent page listing
    each claim with the value to be shared. Voluntary claims start off.
  - `technical`: pick a predefined customer and edit the ID token, with **no
    authentication**. It is the default. Anyone who can reach the
    authorization endpoint can act as any customer, and the server logs a
    warning saying so at startup. Keep that warning and the README caveat.

  The endpoint (`http/authorize.rs`), not the experience, owns the page
  shell and the user's session: `request_uri_ttl` only limits how long the
  browser may take to arrive, then `session_ttl` (5 minutes) applies. An
  expired session gets its own page, with a way back to the client
  (`access_denied`).

  To add an experience, implement the trait, add a `Kind` variant, and
  construct it in `build`.
- `src/store/`: `Store` holds the expiry, single-use, replay and revocation
  rules on top of a `Backend` trait. There are two backends: `memory` (the
  default) and `dynamodb` (feature `aws`). Bearer secrets are keyed by
  their SHA-256 digest. If the signing key and pairwise salt are not
  configured, they are generated and kept in the store. Any new backend must
  pass the `contract` test module.
- `client.rs` and `user.rs` define the `ClientRegistry` and `UserStore`
  traits. Clients come from the config file and, optionally, from the
  ConnectID registry, loaded once at startup (`client_sync.rs`). That load
  is configurable and authenticates with a transport certificate, signing
  key and key id read from local files. Users are a static list. With none
  configured, the built-in fictional demo customers are used (password
  `demo-password`), and a warning is logged.
- `src/lambda.rs` and `src/bin/oxid-lambda.rs` (feature `aws`) run the app
  behind an API Gateway HTTP API. The mTLS client certificate comes from
  `requestContext.authentication.clientCert`.
- Config: `oxid.example.toml` is the reference, and `config.rs` validates
  it. The `[store]` section selects the backend.

## Releases and the infrastructure contract

- CI (`.github/workflows/build.yml`) runs on every PR and push to `main`:
  format, lint, tests with DynamoDB Local, conformance for both
  experiences, and the Lambda package.
- To release: bump `version` in `Cargo.toml`, merge to `main`, then run the
  Build workflow by hand with "Create a GitHub release" ticked. The release
  publishes the Linux binary, `oxid-lambda-<v>-x86_64.zip` and
  `oxid-aws-requirements-<v>.json`, each with a `.sha256`.
- `deploy/aws/requirements.json` (`schema_version` 1) tells `oxid-infra`
  what to build: the table key schema and TTL, the IAM actions, and the
  Lambda runtime and architecture. Change it whenever the store's DynamoDB
  usage or the function's AWS calls change. The DynamoDB tests create their
  table from it. Bumping `schema_version` or adding indexes will make the
  infra plan fail until the module there is updated.

## Known gaps

There is no user registration, single sign-on across requests, dynamic client registration or
client/JWKS refresh while running, and the VC module is not built. Not yet
tested: a full authorization flow on Lambda, API Gateway's TLS policy
against the FAPI checks, and registry client sync on Lambda. This repository
is public.
