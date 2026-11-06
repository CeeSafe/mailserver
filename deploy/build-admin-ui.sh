#!/bin/sh
# Builds the admin UI's image: the frontend is built with vite+ (`vp`) in a temporary copy (the source tree is left
# as it is), and only its Nitro output goes into the image. The output is plain JavaScript, so building on an arm64
# Mac for an amd64 server is fine.
#
#   deploy/build-admin-ui.sh [TAG]          # mailserver-admin-ui:TAG (default: dev)
#
# ADMIN_UI_SOURCE   the frontend (default: ~/dev/CosmoMail/CosmoMailServer/CosmoMailAdmin/frontend)
# ADMIN_UI_IMAGE    the image name (default: mailserver-admin-ui)
# PLATFORM          e.g. linux/amd64 (default: this machine's)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tag=${1:-dev}
source=${ADMIN_UI_SOURCE:-$HOME/dev/CosmoMail/CosmoMailServer/CosmoMailAdmin/frontend}
platform=${PLATFORM:+--platform $PLATFORM}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
(cd "$source" && tar cf - --exclude=node_modules --exclude=.nuxt --exclude=.output .) | (cd "$work" && tar xf -)
(cd "$work" && vp install && vp run build)
printf '*\n!.output\n' > "$work/.dockerignore"
docker buildx build $platform --load -f "$here/admin-ui.Dockerfile" -t "${ADMIN_UI_IMAGE:-mailserver-admin-ui}:$tag" "$work"
