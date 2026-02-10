FROM golang:1.24 AS builder

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /acme-azure ./...

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /acme-azure /acme-azure

# Certificate management configuration
ENV CHECK_INTERVAL=24h
ENV RENEW_BEFORE_DAYS=30
ENV AZURE_CERT_NAME="wildcard-cert"

# Email notification configuration (optional)
ENV NOTIFY_EMAIL_ENABLED="false"
ENV SMTP_PORT="587"

EXPOSE 80

USER nonroot:nonroot

ENTRYPOINT ["/acme-azure"]
