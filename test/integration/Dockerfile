FROM golang:latest AS builder

RUN apt-get update && apt-get install -y clang && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY frost-zm/go/ frost-zm/go/
COPY vultiserver/ vultiserver/

WORKDIR /build/vultiserver

RUN go mod download
RUN CGO_ENABLED=1 CC=clang go build -o /out/api cmd/vultisigner/main.go
RUN CGO_ENABLED=1 CC=clang go build -o /out/worker cmd/worker/main.go

RUN mkdir -p /out/libs && \
    cp /build/frost-zm/go/frozt/includes/linux-amd64/libfroztlib.so /out/libs/ 2>/dev/null || true && \
    cp /build/frost-zm/go/fromt/includes/linux-amd64/libfromtlib.so /out/libs/ 2>/dev/null || true && \
    find /go/pkg/mod -path "*/go-wrappers*/includes/linux/lib*.so" -exec cp {} /out/libs/ \; 2>/dev/null || true && \
    find /go/pkg/mod -path "*/go-wrappers*/includes/linux-amd64/lib*.so" -exec cp {} /out/libs/ \; 2>/dev/null || true && \
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
