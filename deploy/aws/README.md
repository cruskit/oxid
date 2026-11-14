# Running oxID on AWS Lambda

oxID runs as a Lambda function behind an API Gateway HTTP API, with its state
in DynamoDB. This directory says what such a deployment needs. It contains no
infrastructure code: write that in your own project, against a release.

## What a release gives you

| Asset | Use |
| --- | --- |
| `oxid-lambda-v<version>-x86_64.zip` | The function's deployment package. Deploy it unchanged. |
| `oxid-aws-requirements-v<version>.json` | The DynamoDB table and IAM actions that version needs. |
| `*.sha256` | Checksums. Verify before deploying. |

[`requirements.json`](requirements.json) is the same file as the release
asset. A test keeps it in step with the code, and creates its test table from
it, so a table built from the file is one the code works with. Reading it from
infrastructure code (for example with Terraform's `jsondecode(file(...))`)
means an upgrade that changes the table shows up as a change in your plan.

## The pieces

```
              issuer host (no client certificate)
browser ───────────────────────────────┐
                                       ▼
                           API Gateway HTTP API ──► Lambda (bootstrap) ──► DynamoDB table
                                       ▲
client back end ───────────────────────┘
              mTLS host (client certificate required)
```

- **Lambda function.** Runtime `provided.al2023`, architecture `x86_64`,
  handler `bootstrap`. 512 MB and a 15 second timeout are comfortable.
- **Configuration.** The function reads the TOML file named by `OXID_CONFIG`
  (default `oxid.toml` in `/var/task`). The simplest arrangement leaves the
  release zip untouched and ships the configuration in a Lambda layer, where
  it appears under `/opt`: set `OXID_CONFIG=/opt/oxid.toml`. Paths inside the
  file are relative to the file. `server.*` settings are ignored on Lambda.
- **Store.** Set `[store] backend = "dynamodb"` and `table`. Give each oxID
  instance its own table. The function's role needs the actions listed in
  `requirements.json` on that table, and nothing else beyond writing its logs.
- **Signing key and pairwise salt.** Leave `keys.signing_key` and
  `keys.pairwise_salt` unset and oxID creates them on first start and keeps
  them in the table, so every instance of the function uses the same ones.
  Anyone who can read the table can read the signing key: encrypt the table
  and keep read access narrow.
- **API Gateway.** One HTTP API with a `$default` route to the function
  (payload format 2.0) and two custom domain names:
  - the host of `issuer`, without mutual TLS, for browsers and discovery;
  - the host of `mtls_base_url`, with mutual TLS, for the token, PAR and
    UserInfo endpoints.

  Disable the API's default `execute-api` endpoint.
- **Client certificates.** API Gateway validates the certificate against the
  trust store you give the mTLS domain name, and passes it to the function in
  `requestContext.authentication.clientCert`. oxID binds access tokens to its
  thumbprint. It never reads a certificate from a request header. Requests
  through the issuer host carry no certificate and are refused by the
  endpoints that need one.

## Things that differ from the standalone server

- TLS versions and cipher suites are API Gateway's, not oxID's. Choose the
  domain names' security policy accordingly.
- API Gateway requires a trust store, so the standalone server's "accept any
  certificate the client proves possession of" mode is not available: every
  client certificate, or its issuer, must be in the trust store.
- Nothing runs between requests. Expired records are removed by the table's
  TTL setting rather than by a background task.
- Clients loaded from the ConnectID registry are loaded once per cold start.

- Under the `ci` experience the authorization endpoint holds its response
  for up to `ci.response_delay` seconds, inside the request. Give the
  function a timeout comfortably longer than that.

## Trying the DynamoDB store locally

```sh
docker run --rm -p 127.0.0.1:8000:8000 amazon/dynamodb-local
OXID_TEST_DYNAMODB_ENDPOINT=http://127.0.0.1:8000 cargo test --features aws store
```
