# syntax=docker/dockerfile:1.7
#
# The mail server, built with ceesafec (CeeSafe to C, then cc) and run on distroless (glibc, OpenSSL 3, CA roots),
# as a non-root user. Build it with deploy/build-image.sh: the package's path dependencies (CeeSafeLibs, and
# PostgresClient beside this package) come in as named build contexts, in the layout ceesafe.toml expects.
#
# The container listens on unprivileged ports (see deploy/mailserver.toml.example); compose maps the public ones.

ARG CEESAFE_VERSION=v0.21.0

FROM debian:bookworm-slim AS build
ARG CEESAFE_VERSION
ARG TARGETARCH
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends build-essential libssl-dev ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
# The compiler, from its GitHub release, checked against the release's SHA256SUMS.
RUN set -eu; \
    case "$TARGETARCH" in amd64) arch=x64 ;; arm64) arch=arm64 ;; *) echo "no ceesafec for $TARGETARCH" >&2; exit 1 ;; esac; \
    base="https://github.com/CeeSafe/CeeSafe/releases/download/$CEESAFE_VERSION"; \
    cd /tmp; \
    curl -fsSLO "$base/ceesafec-linux-$arch.tar.gz"; \
    curl -fsSLO "$base/SHA256SUMS"; \
    grep " ceesafec-linux-$arch.tar.gz\$" SHA256SUMS | sha256sum -c -; \
    tar -xzf "ceesafec-linux-$arch.tar.gz" -C /usr/local/bin ceesafec; \
    ceesafec --version
COPY --from=ceesafelibs . /src/CeeSafeLibs/
COPY --from=postgresclient . /src/CeeSafeApps/PostgresClient/
COPY . /src/CeeSafeApps/mailserver/
WORKDIR /src/CeeSafeApps/mailserver
RUN ceesafec build -o out/mailserver --cflag -O2 && test -x out/mailserver
# The data directory, owned by distroless's nonroot user (65532), for a named volume to start from.
RUN mkdir -p /data/var/lib/mailserver/blobs /data/var/lib/mailserver/tls && chown -R 65532:65532 /data/var/lib/mailserver

FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=build /src/CeeSafeApps/mailserver/out/mailserver /usr/local/bin/mailserver
COPY --from=build /data/var/lib/mailserver /var/lib/mailserver
# Blobs (message content), the ACME account key and certificates it writes; mount a volume here.
VOLUME ["/var/lib/mailserver"]
# SMTP 25/587/465, IMAP 143/993, HTTP 80/443, and the admin API (the admin UI's server only), as the example config
# has them: unprivileged inside the container.
EXPOSE 2525 2587 2465 2143 2993 8080 8443 9184
USER nonroot
ENTRYPOINT ["/usr/local/bin/mailserver", "--config", "/etc/mailserver/mailserver.toml"]
CMD ["serve"]
