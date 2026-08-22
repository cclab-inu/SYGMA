# Build the manager binary
FROM golang:1.24 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# Cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/
COPY pkg/ pkg/

# Build
# CGO_ENABLED=1 for eBPF
RUN CGO_ENABLED=1 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager cmd/main.go

# Use distroless as minimal base image to package the manager binary
# eBPF requires some libraries, so we use a base image with libc
FROM ubuntu:22.04

# Install necessary libraries for eBPF
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=builder /workspace/manager .

# Run as root for eBPF access
USER root

ENTRYPOINT ["/manager"]