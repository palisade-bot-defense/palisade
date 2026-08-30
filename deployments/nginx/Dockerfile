# syntax=docker/dockerfile:1.7
FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY pkg pkg
COPY internal/proxytlsdiag internal/proxytlsdiag
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go test -c -trimpath -o /out/nginxdiag ./internal/proxytlsdiag

FROM scratch
COPY --from=build /out/nginxdiag /nginxdiag
USER 65532:65532
ENTRYPOINT ["/nginxdiag"]
