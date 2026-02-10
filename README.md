# ACME Azure

Automated Let's Encrypt SSL certificate management for Azure Key Vault. Runs as a sidecar container in Azure Container Apps, handling HTTP-01 challenge verification, PFX conversion, and certificate renewal.

## Architecture

The application runs as a long-lived daemon alongside your UI applications in an Azure Container Apps Environment. An ingress rule routes `/.well-known/acme-challenge/*` traffic to this container while the rest goes to your UI apps.

```
                     Azure Container Apps Environment
                    ┌──────────────────────────────────────────┐
                    │                                          │
                    │  ┌────────────┐    ┌────────────────┐    │
internet ─── LB ───┼─>│ UI App     │    │ UI App         │    │
  │                 │  │ dev.app.com│    │ prd.app.com    │    │
  │                 │  └────────────┘    └────────────────┘    │
  │                 │                                          │
  │ /.well-known/   │  ┌─────────────────┐                    │
  │ acme-challenge/ ┼─>│ acme-azure      │                    │
  │                 │  │ (this container) │                    │
  │                 │  └────────┬────────┘                    │
  │                 │           │                              │
  │                 └───────────┼──────────────────────────────┘
  │                             │
  │                             ▼
  │                 ┌─────────────────────┐
  │                 │ Azure Key Vault     │
  │                 │ ┌─────────────────┐ │
  │                 │ │ wildcard-cert   │ │
  │                 │ └─────────────────┘ │
  │                 └─────────────────────┘
  │                             ▲
  │                             │ Container Apps binds
  └─────────────────────────────┘ cert to custom domains
```

On each cycle (default: every 24 hours) the application:

1. **Checks the certificate** in Azure Key Vault — reads expiration date and compares it against the renewal threshold (default: 30 days before expiry). If still valid, skips to sleep.
2. **Requests a new certificate** from Let's Encrypt via ACME protocol.
3. **Completes the HTTP-01 challenge** — Let's Encrypt sends a request to `http://<domain>/.well-known/acme-challenge/<token>`, the ingress rule routes it to this container, which responds with the verification token.
4. **Converts PEM to PFX** — in-memory using a native Go library (no OpenSSL dependency).
5. **Uploads to Azure Key Vault** — the PFX is base64-encoded and imported via Azure SDK. Container Apps picks up the new certificate for custom domain bindings.
6. **Sleeps** until the next check interval.

If any step fails and email notifications are enabled, the application sends an error report via SMTP and retries on the next cycle.

## Key features

- Automatic SSL certificate generation using Let's Encrypt
- Multi-domain support in a single certificate
- HTTP-01 challenge verification with built-in HTTP server and `/healthz` endpoint
- In-memory PFX conversion (no OpenSSL required)
- Azure Key Vault integration via Azure SDK for Go
- Configurable monitoring interval and renewal threshold
- Graceful shutdown on SIGINT/SIGTERM
- Minimal Docker image (~20 MB, distroless, non-root)
- Optional SMTP error notifications

## Getting started

### Prerequisites

- An Azure subscription — [create one for free](https://azure.microsoft.com/free/)
- An Azure Key Vault instance
- A Service Principal or Managed Identity with the **Key Vault Certificates Officer** role on the Key Vault
- Docker

### Build

```bash
docker build -t acme-azure .
```

### Run locally

```bash
docker run -d \
  -p 80:80 \
  -e DOMAINS="dev.example.com,prd.example.com" \
  -e EMAIL="admin@example.com" \
  -e AZURE_TENANT_ID="<tenant-id>" \
  -e AZURE_CLIENT_ID="<client-id>" \
  -e AZURE_CLIENT_SECRET="<client-secret>" \
  -e AZURE_KEYVAULT_NAME="<keyvault-name>" \
  --name acme-azure \
  acme-azure
```

## Deploy to Azure Container Apps

```bash
az containerapp create \
  --name acme-azure \
  --resource-group mygroup \
  --environment myenv \
  --image <your-registry>/acme-azure:latest \
  --target-port 80 \
  --ingress external \
  --env-vars \
    DOMAINS="dev.example.com,prd.example.com" \
    EMAIL="admin@example.com" \
    AZURE_KEYVAULT_NAME="<keyvault-name>"
```

> [!IMPORTANT]
> Configure an ingress rule in your Container Apps Environment to route `/.well-known/acme-challenge/*` traffic to the `acme-azure` container. Without this, HTTP-01 challenges will fail.

## Configuration

### Required environment variables

| Variable | Description |
|---|---|
| `DOMAINS` | Comma-separated list of domains (e.g. `dev.example.com,prd.example.com`) |
| `EMAIL` | Contact email for Let's Encrypt account registration |
| `AZURE_KEYVAULT_NAME` | Azure Key Vault name |

### Optional environment variables

| Variable | Default | Description |
|---|---|---|
| `AZURE_CERT_NAME` | `wildcard-cert` | Certificate name in Key Vault |
| `CHECK_INTERVAL` | `24h` | How often to check for certificate renewal (Go duration format) |
| `RENEW_BEFORE_DAYS` | `30` | Days before expiration to trigger renewal |
| `PFX_PASSWORD` | *(empty)* | Password for PFX certificate file |
| `NOTIFY_EMAIL_ENABLED` | `false` | Enable SMTP error notifications |
| `SMTP_HOST` | — | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USERNAME` | — | SMTP authentication username |
| `SMTP_PASSWORD` | — | SMTP authentication password |
| `SMTP_FROM` | Same as `EMAIL` | Notification sender address |
| `SMTP_TO` | Same as `EMAIL` | Notification recipient address |

### Authentication

The application uses [`DefaultAzureCredential`](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#NewDefaultAzureCredential), which supports multiple authentication methods in order of priority:

| Method | Required variables |
|---|---|
| Managed Identity (recommended for Container Apps) | None — assigned automatically |
| Service Principal | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |

### Email notifications

Error notifications are disabled by default. To enable:

```bash
NOTIFY_EMAIL_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-specific-password
```

> [!NOTE]
> When using Gmail, enable 2-factor authentication and generate an App Password. Use the App Password as `SMTP_PASSWORD`.

Notifications are sent for certificate processing errors, ACME challenge failures, and Key Vault upload failures.

## Troubleshooting

| Problem | Possible cause | Resolution |
|---|---|---|
| HTTP-01 challenge fails | Port 80 not accessible from the internet | Verify ingress rule routes `/.well-known/acme-challenge/*` to this container |
| HTTP-01 challenge fails | DNS not pointing to the load balancer | Verify DNS records for all domains in `DOMAINS` |
| Key Vault access denied | Insufficient permissions | Ensure the Service Principal has `get` and `import` certificate permissions |
| Certificate not appearing | Upload error | Check container logs for `importing certificate` errors |
| Container restarting | Health check misconfigured | Point the health probe to `/healthz` on port 80 |

## Security considerations

- The container runs as `nonroot` user in a distroless image with no shell
- Port 80 must be accessible from the internet for ACME challenges only during verification
- Store secrets using Azure Key Vault references or Container Apps secrets — avoid plaintext in container configuration
- Use Managed Identity instead of Service Principal credentials where possible
- Rotate Service Principal credentials regularly
- Monitor Key Vault audit logs for certificate operations

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
