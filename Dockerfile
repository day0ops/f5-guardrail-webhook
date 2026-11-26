# stage 1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/f5-guardrail-webhook ./cmd/f5-guardrail-webhook

# stage 2
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/f5-guardrail-webhook /usr/local/bin/f5-guardrail-webhook
USER nonroot:nonroot
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/f5-guardrail-webhook"]
