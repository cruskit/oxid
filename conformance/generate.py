#!/usr/bin/env python3
"""Generate the keys and suite configuration for a conformance run.

Writes into conformance/.generated/ (git-ignored):

* client{1,2}.jwks.json  public keys, read by oxID (see oxid.toml)
* suite-config.json      the conformance suite test configuration, holding
                         the matching private keys and TLS client certificates

Everything here is throwaway test material, regenerated whenever the
directory is missing.
"""

import base64
import datetime
import json
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / ".generated"

ALIAS = "oxid"
ISSUER = "https://oxid:9443"
USERNAME = "demo"
PASSWORD = "demo-password"


def b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def signing_jwk(kid: str) -> tuple[dict, dict]:
    """A PS256 key pair as (private JWK, public JWK)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_numbers()
    pub = priv.public_numbers
    public = {
        "kty": "RSA",
        "use": "sig",
        "alg": "PS256",
        "kid": kid,
        "n": b64url_uint(pub.n),
        "e": b64url_uint(pub.e),
    }
    private = dict(
        public,
        d=b64url_uint(priv.d),
        p=b64url_uint(priv.p),
        q=b64url_uint(priv.q),
        dp=b64url_uint(priv.dmp1),
        dq=b64url_uint(priv.dmq1),
        qi=b64url_uint(priv.iqmp),
    )
    return private, public


def tls_client(common_name: str) -> dict:
    """A self-signed TLS client certificate and key, PEM encoded."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return {
        "cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "key": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    }


CALLBACK = f"https://*/test/a/{ALIAS}/callback*"
AUTHORIZE = f"{ISSUER}/authorize*"


def verify_complete() -> dict:
    """The suite's callback page has finished processing the response."""
    return {
        "task": "Verify Complete",
        "match": CALLBACK,
        "commands": [["wait", "id", "submission_complete", 10]],
    }


def sign_in(button: str) -> dict:
    """Fill in the oxID login form and press `button`."""
    return {
        "task": "Sign in",
        "match": AUTHORIZE,
        "commands": [
            ["text", "id", "username", USERNAME],
            ["text", "id", "password", PASSWORD],
            ["click", "id", button],
        ],
    }


def entry(tasks: list, limit: int | None = None) -> dict:
    """One browser automation entry for visits to the authorization endpoint.

    The suite uses the first matching entry. `limit` caps how many visits an
    entry handles, after which the next matching entry takes over; that is
    how a test's first and second visit get different scripts.
    """
    out = {"match": AUTHORIZE, "tasks": tasks}
    if limit is not None:
        out["match-limit"] = limit
    return out


def login_and(button: str, limit: int | None = None) -> dict:
    """Sign in, press `button`, and land back on the suite's callback."""
    return entry([sign_in(button), verify_complete()], limit)


def redirect_with_error() -> dict:
    """oxID redirects straight back to the suite with an error."""
    return entry([verify_complete()])


def error_page() -> dict:
    """oxID shows an error page instead of redirecting; capture it for the
    screenshot the test asks for."""
    capture = ["wait", "id", "error-message", 10, ".*", "update-image-placeholder"]
    return entry([{"task": "Expect error page", "match": AUTHORIZE, "commands": [capture]}])


def look_only(limit: int) -> dict:
    """Load the login page and do nothing."""
    wait = ["wait", "id", "username", 10]
    return entry([{"task": "Load login page", "match": AUTHORIZE, "commands": [wait]}], limit)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    private1, public1 = signing_jwk("oxid-conformance-1")
    private2, public2 = signing_jwk("oxid-conformance-2")
    (OUT / "client1.jwks.json").write_text(json.dumps({"keys": [public1]}, indent=2))
    (OUT / "client2.jwks.json").write_text(json.dumps({"keys": [public2]}, indent=2))

    prefix = "fapi2-security-profile-final-"
    config = {
        "alias": ALIAS,
        "description": "oxID - FAPI2 Message Signing Final, ConnectID profile",
        "server": {
            "discoveryUrl": f"{ISSUER}/.well-known/openid-configuration",
            # Defined by OpenID Connect for Identity Assurance, which the
            # suite's generic RFC 8414 metadata schema does not know about.
            "allow_unexpected_metadata_fields": ["verified_claims_supported"],
        },
        "client": {"client_id": "oxid-conformance-1", "jwks": {"keys": [private1]}},
        "client2": {"client_id": "oxid-conformance-2", "jwks": {"keys": [private2]}},
        "mtls": tls_client("oxid-conformance-1"),
        "mtls2": tls_client("oxid-conformance-2"),
        # Default browser behaviour: sign in as the demo user and approve.
        "browser": [login_and("approve")],
        "override": {
            prefix + "user-rejects-authentication": {"browser": [login_and("deny")]},
            # First visit only loads the login page; the second signs in.
            prefix + "par-ensure-reused-request-uri-prior-to-auth-completion-succeeds": {
                "browser": [look_only(limit=1), login_and("approve")]
            },
            # request_uri problems cannot be reported by redirect: without a
            # usable request there is no redirect URI that can be trusted.
            prefix + "par-attempt-reuse-request_uri": {
                "browser": [login_and("approve", limit=1), error_page()]
            },
            prefix + "par-attempt-to-use-expired-request_uri": {"browser": [error_page()]},
            prefix + "par-attempt-to-use-request_uri-for-different-client": {
                "browser": [error_page()]
            },
            # Not sent via PAR, but naming a registered redirect URI, so the
            # error can go back to the client.
            prefix + "ensure-unsigned-authorization-request-without-using-par-fails": {
                "browser": [redirect_with_error()]
            },
        },
    }
    (OUT / "suite-config.json").write_text(json.dumps(config, indent=2))
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
