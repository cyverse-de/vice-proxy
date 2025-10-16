# First stage: Build the binary
FROM golang:1.24 AS build-root

WORKDIR /build

# Copy dependency files first for better layer caching
COPY go.mod go.sum ./

RUN go mod download

# Copy source code
COPY . .

# Build static binary with optimizations
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN go build -o vice-proxy -ldflags="-w -s" .

## Second stage: Minimal runtime image
FROM alpine:3.20

# Copy CA certificates from build stage for HTTPS connections to Keycloak
COPY --from=build-root /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary from build stage
COPY --from=build-root /build/vice-proxy /bin/vice-proxy

ENTRYPOINT ["vice-proxy"]
CMD ["--help"]

EXPOSE 8080
