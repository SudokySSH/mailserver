FROM rust:1.80-alpine AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /src/target/release/aether-mime-worker /usr/local/bin/mime-worker
USER nobody
ENTRYPOINT ["mime-worker"]
