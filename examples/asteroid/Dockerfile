FROM golang:1.24 AS build

WORKDIR /src

# Copy go.mod and go.sum first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build for multiple architectures
ARG TARGETPLATFORM
RUN case "${TARGETPLATFORM}" in \
      linux/amd64) GOARCH=amd64 ;; \
      linux/arm64) GOARCH=arm64 ;; \
      *) GOARCH=amd64 ;; \
    esac && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${GOARCH} go build -tags=redis -o asteroid ./cmd/server

FROM alpine:3.19 AS runtime-prep
RUN addgroup -g 65532 -S nonroot && adduser -u 65532 -S nonroot -G nonroot
RUN mkdir -p /app/keys && chown -R nonroot:nonroot /app

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=build /src/asteroid /app/asteroid
COPY --from=build /src/data /app/data
COPY --from=runtime-prep --chown=nonroot:nonroot /app/keys /app/keys

USER nonroot:nonroot

EXPOSE 8880

ENTRYPOINT ["/app/asteroid"]
