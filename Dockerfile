# docker build -t dnstwist .
# docker build -t dnstwist:phash --build-arg phash=1 .

# Build stage
FROM golang:1.24 AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with static linking
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o dnstwist ./cmd/dnstwist

# Final stage - using distroless Debian
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/dnstwist .

# Copy GeoIP database if it exists
COPY --from=builder /app/GeoLite2-Country.mmdb* ./

# Use nonroot user (uid 65532, gid 65532)
USER 65532:65532

# Set entrypoint
ENTRYPOINT ["/app/dnstwist"]
