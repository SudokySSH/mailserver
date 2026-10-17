# Сборка
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aether-api .

# Запуск. docker-cli нужен для `docker exec mailserver setup ...`.
FROM alpine:3.20
RUN apk add --no-cache docker-cli ca-certificates tzdata
COPY --from=build /out/aether-api /usr/local/bin/aether-api
USER root
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --retries=10 \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null 2>&1 || exit 1
ENTRYPOINT ["aether-api"]
