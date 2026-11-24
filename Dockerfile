# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -ldflags="-s -w" -o /out/link-manager ./cmd/manager
RUN mkdir -p /image/data && touch /image/data/.keep

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/link-manager /link-manager
COPY --from=build --chown=65532:65532 /image/data /data
USER 65532:65532
ENV DATA_DIR=/data
EXPOSE 8080
ENTRYPOINT ["/link-manager"]
