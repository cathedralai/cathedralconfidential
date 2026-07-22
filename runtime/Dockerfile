# syntax=docker/dockerfile:1.7
# Each external filesystem is pinned to the exact linux/amd64 manifest, not a
# mutable tag. The resulting workload image must still be published and pinned
# by its own sha256 digest in the launch policy before any job is admitted.
FROM --platform=linux/amd64 docker.io/library/golang:1.25.12-bookworm@sha256:eecd15e52d06149b84ac1caa56cfd07f584da6803e5621a77024f38827f342ec AS go-build
WORKDIR /src
COPY cmd/cathedral-confidential-space/go.mod ./go.mod
COPY cmd/cathedral-confidential-space/ ./
ARG CONFIG_SIGNING_KEY_ID
ARG CONFIG_SIGNING_PUBLIC_KEY_BASE64
ARG WORKLOAD_ATTESTATION_AUDIENCE
ARG TARGETOS
ARG TARGETARCH
RUN test "${TARGETOS}/${TARGETARCH}" = "linux/amd64" && \
    test -n "${CONFIG_SIGNING_KEY_ID}" && test -n "${CONFIG_SIGNING_PUBLIC_KEY_BASE64}" && \
    test -n "${WORKLOAD_ATTESTATION_AUDIENCE}" && \
    test "${WORKLOAD_ATTESTATION_AUDIENCE}" != "https://sts.google.com" && \
    CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false \
      -ldflags="-s -w -X main.configSigningKeyID=${CONFIG_SIGNING_KEY_ID} -X main.configSigningPublicKeyBase64=${CONFIG_SIGNING_PUBLIC_KEY_BASE64} -X main.workloadAudience=${WORKLOAD_ATTESTATION_AUDIENCE}" \
      -o /out/cathedral-confidential-space-collector ./cmd/collector

FROM --platform=linux/amd64 docker.io/library/python:3.12.10-bookworm@sha256:8191c572cf979a5dbc7345474ed93d96c56a6ac95c1dae2451132fe1ba633ae3
COPY --from=go-build --chmod=0555 /out/cathedral-confidential-space-collector /opt/cathedral/bin/cathedral-confidential-space-collector
COPY --chmod=0555 runtime/cathedral-job /opt/cathedral/bin/cathedral-job
# The public KBS CA is an explicit BuildKit input and is persisted in the image;
# private keys must never enter this image or its build context.
RUN --mount=type=secret,id=kbs_root_ca,required=true \
    install -D -m 0444 /run/secrets/kbs_root_ca /etc/cathedral/kbs-root.pem && \
    ln -s /usr/local/bin/python3.12 /usr/bin/python3 && \
    install -d -o root -g root -m 0555 /work && \
    dpkg-query -W -f='${Status}' util-linux | grep -qx 'install ok installed' && \
    test -x /usr/bin/unshare && test -x /usr/bin/setpriv && test -x /usr/bin/python3 && \
    ! ldd /usr/bin/unshare | grep -q 'not found' && \
    ! ldd /usr/bin/setpriv | grep -q 'not found' && \
    test -d /run && test -d /tmp && \
    test -f /etc/ssl/certs/ca-certificates.crt && \
    python3 -m py_compile /opt/cathedral/bin/cathedral-job
USER 0:0
ENTRYPOINT ["/opt/cathedral/bin/cathedral-confidential-space-collector", "run"]
