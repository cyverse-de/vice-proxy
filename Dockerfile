# First stage
FROM golang:1.21 as build-root

WORKDIR /build

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN go build ./...

## Second stage
FROM golang:1.21

COPY --from=build-root /build/vice-proxy /bin/vice-proxy

ENTRYPOINT ["vice-proxy"]
CMD ["--help"]

EXPOSE 8080
