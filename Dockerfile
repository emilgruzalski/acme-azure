FROM golang:1.24

# Install OpenSSL for PFX conversion
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -v -o /usr/local/bin/certbot-azure ./...

# Create directory for ACME challenge files
RUN mkdir -p /.well-known/acme-challenge

# Certificate management configuration
ENV CHECK_INTERVAL=24h
ENV RENEW_BEFORE_DAYS=30
ENV PFX_PASSWORD=""
ENV DOMAINS="dev.example.com,test.example.com,prd.example.com"
ENV EMAIL="admin@example.com"

# Azure configuration
ENV AZURE_TENANT_ID=""
ENV AZURE_CLIENT_ID=""
ENV AZURE_CLIENT_SECRET=""
ENV AZURE_SUBSCRIPTION_ID=""
ENV AZURE_KEYVAULT_NAME=""
ENV AZURE_CERT_NAME="wildcard-cert"

# Email notification configuration (optional)
ENV NOTIFY_EMAIL_ENABLED="false"
ENV SMTP_HOST=""
ENV SMTP_PORT="587"
ENV SMTP_USERNAME=""
ENV SMTP_PASSWORD=""
ENV SMTP_FROM=""
ENV SMTP_TO=""

CMD ["certbot-azure"]