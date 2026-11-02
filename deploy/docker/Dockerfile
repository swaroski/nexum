# Build:  docker build -f deploy/docker/Dockerfile -t nexum .
FROM rust:1.87-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p nexum

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /data nexum \
    && mkdir -p /data && chown nexum /data
COPY --from=build /src/target/release/nexum /usr/local/bin/nexum
USER nexum
WORKDIR /data
ENV NEXUM_CONFIG=/data/nexum.yaml
EXPOSE 8080
ENTRYPOINT ["nexum"]
CMD ["gateway", "start"]
