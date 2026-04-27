FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o npm-proxy ./cmd/proxy

FROM alpine:3.19

RUN addgroup -S proxy && adduser -S proxy -G proxy

WORKDIR /app
COPY --from=builder /build/npm-proxy .
COPY configs/ configs/

USER proxy
EXPOSE 8080

ENTRYPOINT ["./npm-proxy"]
CMD ["-config", "configs/proxy.yaml"]
