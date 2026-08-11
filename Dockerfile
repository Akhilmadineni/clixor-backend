# syntax=docker/dockerfile:1.7
FROM golang:1.26.5-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/clustr-api ./cmd/api && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/clustr-migrate ./cmd/migrate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/clustr-api /clustr-api
COPY --from=build /out/clustr-migrate /clustr-migrate
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/clustr-api"]
