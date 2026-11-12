#!/usr/bin/env bash
# Run the OpenID Foundation conformance suite against oxID.
#
# Builds oxID into a container, starts it next to the prebuilt conformance
# suite images, and drives the suite's own run-test-plan.py with the
# FAPI2 Message Signing (Final) plan in its ConnectID variant.
#
# The user experience at the authorization endpoint is pluggable, and what it
# does decides what ends up in the tokens, so the whole plan is run once per
# experience, each with browser automation written for it.
#
# Usage: scripts/conformance.sh [extra run-test-plan.py arguments]
#
# Environment:
#   OXID_EXPERIENCE  run for this experience only (technical or login);
#                    unset runs each in turn
#   SUITE_TAG        conformance suite release (image tag and git tag)
#   SUITE_HOST_PORT  loopback port for the suite UI/API       (default 8943)
#   OXID_HOST_PORT   loopback port for oxID's public listener  (default 9443)
#   KEEP_RUNNING=1   leave the containers up afterwards, to browse results at
#                    https://localhost:$SUITE_HOST_PORT/
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="$ROOT/conformance"
CACHE="$CONF/.cache"

EXPERIENCES=(technical login)

# With no experience chosen, run this script once for each.
if [[ -z "${OXID_EXPERIENCE:-}" ]]; then
  failed=()
  for experience in "${EXPERIENCES[@]}"; do
    printf '\n######## Conformance suite: %s experience ########\n' "$experience"
    OXID_EXPERIENCE="$experience" "${BASH_SOURCE[0]}" "$@" || failed+=("$experience")
  done
  if ((${#failed[@]})); then
    printf '\nConformance suite FAILED for: %s\n' "${failed[*]}" >&2
    exit 1
  fi
  printf '\nConformance suite passed for: %s\n' "${EXPERIENCES[*]}"
  exit 0
fi

if [[ ! " ${EXPERIENCES[*]} " == *" $OXID_EXPERIENCE "* ]]; then
  echo "Unknown OXID_EXPERIENCE '$OXID_EXPERIENCE' (expected one of: ${EXPERIENCES[*]})" >&2
  exit 2
fi
export OXID_EXPERIENCE
RESULTS="$CONF/results/$OXID_EXPERIENCE"
SUITE_CONFIG="$CONF/.generated/suite-config-$OXID_EXPERIENCE.json"

export SUITE_TAG="${SUITE_TAG:-release-v5.3.4}"
export SUITE_HOST_PORT="${SUITE_HOST_PORT:-8943}"
export OXID_HOST_PORT="${OXID_HOST_PORT:-9443}"

SUITE_REPO="https://gitlab.com/openid/conformance-suite.git"
SUITE_SRC="$CACHE/suite-$SUITE_TAG"
VENV="$CACHE/venv"
SUITE_URL="https://localhost:$SUITE_HOST_PORT/"

PLAN='fapi2-message-signing-final-test-plan'
PLAN+='[openid=openid_connect]'
PLAN+='[client_auth_type=private_key_jwt]'
PLAN+='[fapi_request_method=signed_non_repudiation]'
PLAN+='[sender_constrain=mtls]'
PLAN+='[fapi_profile=connectid_au]'
PLAN+='[fapi_response_mode=plain_response]'

compose() { docker compose -f "$CONF/docker-compose.yml" "$@"; }
log() { printf '\n==> %s\n' "$*"; }

mkdir -p "$CACHE" "$RESULTS"

# The suite's runner script and its helper modules, at the pinned release.
if [[ ! -f "$SUITE_SRC/scripts/run-test-plan.py" ]]; then
  log "Fetching conformance suite scripts ($SUITE_TAG)"
  rm -rf "$SUITE_SRC"
  git clone --quiet --depth 1 --branch "$SUITE_TAG" --filter=blob:none --sparse \
    "$SUITE_REPO" "$SUITE_SRC"
  git -C "$SUITE_SRC" sparse-checkout set scripts
fi

if [[ ! -x "$VENV/bin/python" ]]; then
  log "Creating Python environment"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install --quiet -r "$SUITE_SRC/scripts/requirements.txt" cryptography
fi

if [[ ! -f "$SUITE_CONFIG" ]]; then
  log "Generating client keys and suite configuration"
  "$VENV/bin/python" "$CONF/generate.py"
fi

cleanup() {
  status=$?
  if [[ "${KEEP_RUNNING:-0}" == "1" ]]; then
    log "Leaving containers running; suite UI at $SUITE_URL"
  else
    log "Stopping containers"
    compose logs --no-color oxid >"$RESULTS/oxid.log" 2>&1 || true
    compose logs --no-color server >"$RESULTS/suite.log" 2>&1 || true
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

log "Building oxID and starting containers"
compose up --detach --build --quiet-pull

wait_for() {
  local name="$1" url="$2" tries="${3:-120}"
  log "Waiting for $name"
  for ((i = 0; i < tries; i++)); do
    if curl --silent --insecure --fail --output /dev/null --max-time 5 "$url"; then
      return 0
    fi
    sleep 2
  done
  echo "$name did not become ready at $url" >&2
  compose logs --no-color --tail 50 >&2 || true
  return 1
}
wait_for "oxID" "https://localhost:$OXID_HOST_PORT/healthz" 60
wait_for "conformance suite" "${SUITE_URL}api/runner/available" 150

log "Running $PLAN ($OXID_EXPERIENCE experience)"
cd "$SUITE_SRC/scripts"
# CONFORMANCE_DEV_MODE: the local suite has no API authentication and a
# self-signed certificate.
CONFORMANCE_SERVER="$SUITE_URL" \
CONFORMANCE_DEV_MODE=1 \
  "$VENV/bin/python" run-test-plan.py \
  --export-dir "$RESULTS" \
  --expected-failures-file "$CONF/expected-failures.json" \
  --expected-skips-file "$CONF/expected-skips.json" \
  --verbose \
  "$@" \
  "$PLAN" "$SUITE_CONFIG"
