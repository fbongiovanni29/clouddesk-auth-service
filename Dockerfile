# ── build stage ─────────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /auth-service .

# ── runtime stage ────────────────────────────────────────────────────────────────
FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=build /auth-service /usr/local/bin/auth-service
EXPOSE 8080
ENTRYPOINT ["auth-service"]
