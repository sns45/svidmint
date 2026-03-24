FROM golang:1.23-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=1 go build -ldflags "-s -w -X main.version=${VERSION}" -o svidmint ./cmd/svidmint

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 1000 svidmint
COPY --from=builder /build/svidmint /usr/local/bin/svidmint
USER svidmint
ENTRYPOINT ["svidmint"]
