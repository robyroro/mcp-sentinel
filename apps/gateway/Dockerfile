FROM golang:1.20-alpine AS build
WORKDIR /src
COPY apps/gateway/go.mod ./
COPY apps/gateway/cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sentinel-gateway ./cmd/sentinel-gateway

FROM alpine:3.22
RUN apk add --no-cache ca-certificates \
    && addgroup -g 65532 sentinel \
    && adduser -D -u 65532 -G sentinel sentinel
COPY --from=build /out/sentinel-gateway /usr/local/bin/sentinel-gateway
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD wget -q -O - http://localhost:8080/healthz >/dev/null || exit 1
ENTRYPOINT ["sentinel-gateway"]
CMD ["http"]
