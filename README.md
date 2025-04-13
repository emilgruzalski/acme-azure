# Certbot Azure

A Go application that automatically manages Let's Encrypt SSL certificates for multiple domains and stores them in Azure Key Vault. The application handles HTTP-01 challenge verification, converts certificates to PFX format, and automatically renews certificates when needed.

## Features

- Automatic SSL certificate generation using Let's Encrypt
- Supports multiple domains in a single certificate
- HTTP-01 challenge verification
- Automatic conversion to PFX format
- Azure Key Vault integration
- Continuous certificate monitoring and renewal
- Docker support

## Prerequisites

- Azure subscription
- Azure Key Vault instance
- Azure Service Principal with appropriate permissions
- Docker
- Nginx or another reverse proxy for handling HTTP-01 challenges

## Azure Setup

1. Create an Azure Service Principal:
```bash
az ad sp create-for-rbac --name "certbot-azure" --role "Key Vault Certificates Officer"
```

2. Note down the following values:
   - Client ID (appId)
   - Client Secret (password)
   - Tenant ID (tenant)

3. Grant the Service Principal access to your Key Vault:
```bash
az keyvault set-policy --name YOUR_KEYVAULT_NAME \
    --object-id SERVICE_PRINCIPAL_OBJECT_ID \
    --certificate-permissions get list create import delete \
    --secret-permissions get list set delete
```

## Environment Variables

| Variable | Description | Example | Default |
|----------|-------------|---------|---------|
| DOMAINS | Comma-separated list of domains | "dev.example.com,test.example.com,prd.example.com" | - |
| EMAIL | Contact email for Let's Encrypt | "admin@example.com" | - |
| AZURE_TENANT_ID | Azure Tenant ID | "00000000-0000-0000-0000-000000000000" | - |
| AZURE_CLIENT_ID | Service Principal Client ID | "00000000-0000-0000-0000-000000000000" | - |
| AZURE_CLIENT_SECRET | Service Principal Secret | "your-secret" | - |
| AZURE_KEYVAULT_NAME | Azure Key Vault name | "my-keyvault" | - |
| AZURE_CERT_NAME | Certificate name in Key Vault | "wildcard-cert" | - |
| CHECK_INTERVAL | How often to check for certificate renewal | "24h" | "24h" |
| RENEW_BEFORE_DAYS | Days before expiration to renew certificate | "30" | "30" |
| PFX_PASSWORD | Password for PFX certificate file | "your-password" | "" (no password) |
| NOTIFY_EMAIL_ENABLED | Enable email notifications for errors | "true" | "false" |
| SMTP_HOST | SMTP server hostname | "smtp.gmail.com" | - |
| SMTP_PORT | SMTP server port | "587" | "587" |
| SMTP_USERNAME | SMTP authentication username | "user@example.com" | - |
| SMTP_PASSWORD | SMTP authentication password | "your-password" | - |
| SMTP_FROM | Email sender address | "sender@example.com" | Same as EMAIL |
| SMTP_TO | Email recipient address | "recipient@example.com" | Same as EMAIL |

## Docker Setup

1. Build the Docker image:
```bash
docker build -t certbot-azure .
```

2. Run the container:
```bash
docker run -d \
  -p 80:80 \
  -e DOMAINS="dev.example.com,test.example.com,prd.example.com" \
  -e EMAIL="admin@example.com" \
  -e AZURE_TENANT_ID="your-tenant-id" \
  -e AZURE_CLIENT_ID="your-client-id" \
  -e AZURE_CLIENT_SECRET="your-client-secret" \
  -e AZURE_KEYVAULT_NAME="your-keyvault-name" \
  -e AZURE_CERT_NAME="wildcard-cert" \
  -e CHECK_INTERVAL="24h" \
  --name certbot-azure \
  certbot-azure
```

## Nginx Configuration

Add the following location block to your Nginx configuration to proxy ACME challenge requests:

```nginx
location /.well-known/acme-challenge/ {
    proxy_pass http://certbot-azure-container/.well-known/acme-challenge/;
    proxy_set_header Host $host;
}
```

Make sure to replace `certbot-azure-container` with the appropriate hostname or IP address where your container is running.

## Azure Container Apps Deployment

1. Create an Azure Container Registry (ACR) and push the image:
```bash
az acr create --name myacr --resource-group mygroup --sku Basic
az acr login --name myacr
docker tag certbot-azure myacr.azurecr.io/certbot-azure:latest
docker push myacr.azurecr.io/certbot-azure:latest
```

2. Deploy to Azure Container Apps:
```bash
az containerapp create \
  --name certbot-azure \
  --resource-group mygroup \
  --environment myenv \
  --image myacr.azurecr.io/certbot-azure:latest \
  --target-port 80 \
  --ingress external \
  --env-vars \
    DOMAINS="dev.example.com,test.example.com,prd.example.com" \
    EMAIL="admin@example.com" \
    AZURE_TENANT_ID="your-tenant-id" \
    AZURE_CLIENT_ID="your-client-id" \
    AZURE_CLIENT_SECRET="your-client-secret" \
    AZURE_KEYVAULT_NAME="your-keyvault-name" \
    AZURE_CERT_NAME="wildcard-cert"
```

## Certificate Management

The application will:
1. Generate a certificate for all specified domains using HTTP-01 challenge
2. Convert the certificate to PFX format
3. Upload it to Azure Key Vault
4. Check periodically (default: every 24 hours) if renewal is needed
5. Automatically renew and update the certificate in Key Vault when necessary

You can access the certificate in Azure Key Vault and use it in your Azure services that support Key Vault integration.

## Email Notifications

The application can send email notifications when errors occur during certificate processing. This feature is disabled by default and can be enabled by setting `NOTIFY_EMAIL_ENABLED=true`.

### Setting up email notifications

1. Enable the feature:
```bash
NOTIFY_EMAIL_ENABLED=true
```

2. Configure SMTP settings:
```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587  # Default port for TLS
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-specific-password
```

3. (Optional) Configure sender and recipient addresses:
```bash
SMTP_FROM=sender@example.com  # Defaults to EMAIL if not set
SMTP_TO=recipient@example.com  # Defaults to EMAIL if not set
```

### Using Gmail

If you're using Gmail as your SMTP server:
1. Enable 2-factor authentication on your Google Account
2. Generate an App Password for this application
3. Use the App Password as SMTP_PASSWORD

### Notification Events

The application will send email notifications for:
- Certificate processing errors
- ACME challenge failures
- Azure Key Vault upload failures

Each notification includes:
- The affected domains
- Detailed error description
- Timestamp of the error

## Troubleshooting

1. HTTP-01 Challenge Fails:
   - Verify that port 80 is accessible
   - Check Nginx proxy configuration
   - Ensure DNS records are correctly configured

2. Azure Key Vault Access Issues:
   - Verify Service Principal credentials
   - Check Key Vault access policies
   - Ensure network access to Key Vault is allowed

3. Certificate Not Appearing in Key Vault:
   - Check application logs for errors
   - Verify Key Vault permissions
   - Ensure certificate name is unique

## Security Considerations

- The application requires access to port 80 for ACME challenges
- Store Azure credentials securely using environment variables or Azure-managed identities
- Use network security groups to restrict access to the container
- Regularly rotate the Service Principal credentials
- Monitor Key Vault audit logs for certificate operations

## License

MIT License
