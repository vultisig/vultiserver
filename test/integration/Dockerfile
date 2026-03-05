FROM rust:latest AS rust-builder

RUN apt-get update && apt-get install -y clang && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY frost-zm/ frost-zm/

WORKDIR /build/frost-zm
RUN cargo build --release -p frozt-lib -p fromt-lib

RUN mkdir -p /out/libs && \
    cp target/release/libfroztlib.so /out/libs/ && \
    cp target/release/libfromtlib.so /out/libs/

RUN mkdir -p /out/frozt-includes /out/fromt-includes && \
    cp target/release/libfroztlib.so /out/frozt-includes/ && \
    cp target/release/libfromtlib.so /out/fromt-includes/

FROM golang:latest AS builder

RUN apt-get update && apt-get install -y clang && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY frost-zm/go/ frost-zm/go/
COPY --from=rust-builder /out/frozt-includes/libfroztlib.so frost-zm/go/frozt/includes/linux-amd64/
COPY --from=rust-builder /out/fromt-includes/libfromtlib.so frost-zm/go/fromt/includes/linux-amd64/

COPY vultiserver/ vultiserver/

WORKDIR /build/vultiserver

RUN sed -i 's|github.com/vultisig/frost-zm/go => .*|github.com/vultisig/frost-zm/go => /build/frost-zm/go|' go.mod
RUN go mod download
RUN CGO_ENABLED=1 CC=clang go build -o /out/api cmd/vultisigner/main.go
RUN CGO_ENABLED=1 CC=clang go build -o /out/worker cmd/worker/main.go

RUN mkdir -p /out/libs && \
    ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then LIBARCH="linux-arm64"; else LIBARCH="linux-amd64"; fi && \
    cp /build/frost-zm/go/frozt/includes/$LIBARCH/libfroztlib.so /out/libs/ 2>/dev/null || true && \
    cp /build/frost-zm/go/fromt/includes/$LIBARCH/libfromtlib.so /out/libs/ 2>/dev/null || true && \
    find /go/pkg/mod -path "*/go-wrappers*/includes/linux/lib*.so" -exec cp {} /out/libs/ \; 2>/dev/null || true && \
    find /go/pkg/mod -path "*/go-wrappers*/includes/$LIBARCH/lib*.so" -exec cp {} /out/libs/ \; 2>/dev/null || true && \
    ls -la /out/libs/

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/api /out/worker ./
COPY --from=builder /out/libs/ /usr/local/lib/
RUN ldconfig

RUN useradd --system --no-create-home appuser

COPY vultiserver/test/integration/entrypoint.sh ./
COPY vultiserver/test/integration/config.yaml ./config.yaml
RUN chmod +x entrypoint.sh && chown -R appuser /app

USER appuser

ENV LD_LIBRARY_PATH=/usr/local/lib

CMD ["./entrypoint.sh"]
