#!/usr/bin/env python3
"""Play the relying party's test code for a conformance run of the `ci`
experience.

Under `ci` nobody clicks anything: oxID answers each authorization request by
itself, by default with a success. Two of the suite's test modules need a
different answer, and only the client that pushed a request may choose one,
at oxID's /ci/response endpoint. The suite is that client but knows nothing
of the endpoint, so this script stands in for it, with the client keys that
conformance/generate.py made for the run:

* user-rejects-authentication: the user refuses, so the response is the
  `access_denied` error.
* par-ensure-reused-request-uri-prior-to-auth-completion-succeeds: the user
  looks at the first page and does nothing, so the first visit is abandoned.

It watches the suite for those modules, reads the `request_uri` of each
pushed request from the module's log, and chooses the response while oxID is
holding its default one back (`ci.response_delay`). Every other module gets
the default response, after the delay.
"""

import argparse
import base64
import json
import re
import secrets
import sys
import time

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PREFIX = "fapi2-security-profile-final-"
# Test module -> the outcome to choose for each request it pushes.
OUTCOMES = {
    PREFIX + "user-rejects-authentication": "error",
    PREFIX + "par-ensure-reused-request-uri-prior-to-auth-completion-succeeds": "abandon",
}
REQUEST_URI = re.compile(r"urn:ietf:params:oauth:request_uri:[A-Za-z0-9_-]+")
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
POLL_SECONDS = 0.25


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_int(text: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)), "big")


def private_key(jwk: dict) -> rsa.RSAPrivateKey:
    number = lambda name: b64url_int(jwk[name])  # noqa: E731
    public = rsa.RSAPublicNumbers(number("e"), number("n"))
    return rsa.RSAPrivateNumbers(
        number("p"), number("q"), number("d"), number("dp"), number("dq"), number("qi"), public
    ).private_key()


def client_assertion(client: dict, issuer: str) -> str:
    """A private_key_jwt assertion, as for the PAR endpoint (PS256)."""
    jwk = client["jwks"]["keys"][0]
    now = int(time.time())
    header = {"alg": "PS256", "typ": "JWT", "kid": jwk["kid"]}
    claims = {
        "iss": client["client_id"],
        "sub": client["client_id"],
        "aud": issuer,
        "jti": secrets.token_urlsafe(16),
        "iat": now,
        "exp": now + 60,
    }
    signed = ".".join(b64url(json.dumps(part).encode()) for part in (header, claims))
    signature = private_key(jwk).sign(
        signed.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256.digest_size),
        hashes.SHA256(),
    )
    return f"{signed}.{b64url(signature)}"


def choose(http: httpx.Client, oxid: str, issuer: str, clients: list, request_uri: str, outcome: str) -> bool:
    """Choose the response to a request, as whichever client pushed it."""
    for client in clients:
        response = http.post(
            f"{oxid}/ci/response",
            data={
                "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": client_assertion(client, issuer),
                "request_uri": request_uri,
                "outcome": outcome,
            },
        )
        if response.status_code == 200:
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--suite", required=True, help="base URL of the conformance suite")
    parser.add_argument("--oxid", required=True, help="base URL of oxID, as this host reaches it")
    parser.add_argument("--config", required=True, help="the suite configuration of the run")
    args = parser.parse_args()

    with open(args.config, encoding="utf-8") as file:
        config = json.load(file)
    issuer = config["server"]["discoveryUrl"].removesuffix("/.well-known/openid-configuration")
    clients = [config["client"], config["client2"]]
    suite = args.suite.rstrip("/")
    oxid = args.oxid.rstrip("/")

    names: dict[str, str] = {}  # test id -> test module name
    done: set[str] = set()  # request URIs already dealt with
    # Both ends use throwaway self-signed certificates.
    with httpx.Client(verify=False, timeout=10) as http:
        while True:
            time.sleep(POLL_SECONDS)
            try:
                for test_id in http.get(f"{suite}/api/runner/running").json():
                    if test_id not in names:
                        info = http.get(f"{suite}/api/info/{test_id}").json()
                        names[test_id] = info.get("testName", "")
                    outcome = OUTCOMES.get(names[test_id])
                    if outcome is None:
                        continue
                    log = http.get(f"{suite}/api/log/{test_id}").text
                    for request_uri in dict.fromkeys(REQUEST_URI.findall(log)):
                        if request_uri in done:
                            continue
                        done.add(request_uri)
                        chosen = choose(http, oxid, issuer, clients, request_uri, outcome)
                        print(
                            f"ci-client: {names[test_id]}: {outcome} "
                            f"{'chosen' if chosen else 'REFUSED'} for {request_uri[-8:]}",
                            flush=True,
                        )
            except (httpx.HTTPError, ValueError) as error:
                # The suite is starting, stopping or busy. Try again.
                print(f"ci-client: {error!r}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
