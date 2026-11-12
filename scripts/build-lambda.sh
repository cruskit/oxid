#!/usr/bin/env bash
# Build the AWS Lambda deployment package into dist/lambda/oxid-lambda.zip.
# Needs only Docker. See deploy/aws/README.md.
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:-dist/lambda}"
mkdir -p "$out"

DOCKER_BUILDKIT=1 docker build \
  --file Dockerfile.lambda \
  --output "type=local,dest=$out" \
  .

cp deploy/aws/requirements.json "$out/oxid-aws-requirements.json"
(cd "$out" && sha256sum oxid-lambda.zip oxid-aws-requirements.json >SHA256SUMS)
ls -l "$out"
