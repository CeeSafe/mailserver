#!/bin/sh
# Builds the mail server's image, and the admin UI's (CosmoMailAdmin's Nuxt frontend, unchanged).
#
#   deploy/build-image.sh [TAG]                 # mailserver:TAG and mailserver-admin-ui:TAG (default: dev)
#
# MAILSERVER_IMAGE / ADMIN_UI_IMAGE   image names (default: mailserver, mailserver-admin-ui)
# ADMIN_UI_SOURCE                     the frontend (default: ~/dev/CosmoMail/CosmoMailServer/CosmoMailAdmin/frontend);
#                                     empty skips the admin UI
# PLATFORM                            e.g. linux/amd64 for a VPS from an arm64 Mac (default: this machine's)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
tag=${1:-dev}
platform=${PLATFORM:+--platform $PLATFORM}
admin_ui=${ADMIN_UI_SOURCE-$HOME/dev/CosmoMail/CosmoMailServer/CosmoMailAdmin/frontend}

# ceesafe.toml's path dependencies: ../PostgresClient and ../../CeeSafeLibs/*.
docker buildx build $platform --load \
    --build-context ceesafelibs="$root/../../CeeSafeLibs" \
    --build-context postgresclient="$root/../PostgresClient" \
    -t "${MAILSERVER_IMAGE:-mailserver}:$tag" "$root"

if [ -n "$admin_ui" ]; then
    ADMIN_UI_SOURCE="$admin_ui" "$here/build-admin-ui.sh" "$tag"
fi
