#!/bin/sh
# Runs the specs under OpenResty in a container. Needs docker.
set -eu
cd "$(dirname "$0")/.."
sh test/fixtures.sh
docker run --rm -v "$PWD:/work" -w /work openresty/openresty:bookworm-fat sh test/run-in-container.sh
