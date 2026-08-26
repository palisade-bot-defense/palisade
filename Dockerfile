# syntax=docker/dockerfile:1.7
FROM node:24.15.0-alpine AS ui
WORKDIR /src
RUN npm install --global pnpm@11.24.0
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY sensor/package.json sensor/package.json
COPY dashboard/package.json dashboard/package.json
RUN pnpm install --frozen-lockfile
COPY sensor sensor
COPY dashboard dashboard
COPY internal/adminui internal/adminui
RUN pnpm build

FROM golang:1.27.0-alpine AS build
ARG VERSION=0.1.0-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/internal/adminui/dist ./internal/adminui/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/palisade ./cmd/palisade

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/palisade /palisade
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/palisade"]
CMD ["serve", "--listen", "0.0.0.0:8080"]
