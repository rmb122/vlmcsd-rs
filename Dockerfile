FROM rust:1.96-alpine AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM scratch
COPY --from=builder /build/target/release/vlmcsd-rs /vlmcsd-rs
COPY vlmcsd.toml /etc/vlmcsd-rs/vlmcsd.toml
USER 65532:65532
EXPOSE 1688/tcp
ENTRYPOINT ["/vlmcsd-rs"]
CMD ["--config", "/etc/vlmcsd-rs/vlmcsd.toml"]
