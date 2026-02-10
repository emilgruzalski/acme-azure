package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

type User struct {
	Email        string
	Registration *registration.Resource
	key          *rsa.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

type EmailConfig struct {
	Enabled   bool
	SMTPHost  string
	SMTPPort  string
	Username  string
	Password  string
	FromEmail string
	ToEmail   string
}

func getEmailConfig() EmailConfig {
	return EmailConfig{
		Enabled:   os.Getenv("NOTIFY_EMAIL_ENABLED") == "true",
		SMTPHost:  os.Getenv("SMTP_HOST"),
		SMTPPort:  getEnvWithDefault("SMTP_PORT", "587"),
		Username:  os.Getenv("SMTP_USERNAME"),
		Password:  os.Getenv("SMTP_PASSWORD"),
		FromEmail: getEnvWithDefault("SMTP_FROM", os.Getenv("EMAIL")), // Default to the Let's Encrypt email
		ToEmail:   getEnvWithDefault("SMTP_TO", os.Getenv("EMAIL")),   // Default to the Let's Encrypt email
	}
}

func sendErrorNotification(config EmailConfig, subject, message string) error {
	if !config.Enabled {
		return nil
	}

	if config.SMTPHost == "" || config.Username == "" || config.Password == "" {
		return fmt.Errorf("incomplete SMTP configuration")
	}

	auth := smtp.PlainAuth("", config.Username, config.Password, config.SMTPHost)

	body := fmt.Sprintf("Subject: %s\r\n"+
		"From: %s\r\n"+
		"To: %s\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", subject, config.FromEmail, config.ToEmail, message)

	err := smtp.SendMail(
		config.SMTPHost+":"+config.SMTPPort,
		auth,
		config.FromEmail,
		[]string{config.ToEmail},
		[]byte(body),
	)

	if err != nil {
		log.Printf("Failed to send notification email: %v", err)
		return err
	}

	log.Printf("Notification email sent successfully to %s", config.ToEmail)
	return nil
}

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	checkInterval := getEnvDuration("CHECK_INTERVAL", 24*time.Hour)
	renewBeforeDays := getEnvInt("RENEW_BEFORE_DAYS", 30)
	domains := strings.Split(os.Getenv("DOMAINS"), ",")

	// Validate domains
	if len(domains) == 0 || (len(domains) == 1 && domains[0] == "") {
		log.Fatal("No domains specified. Please set DOMAINS environment variable")
	}

	email := os.Getenv("EMAIL")
	if email == "" {
		log.Fatal("No email specified. Please set EMAIL environment variable")
	}

	keyVaultName := os.Getenv("AZURE_KEYVAULT_NAME")
	if keyVaultName == "" {
		log.Fatal("No Key Vault name specified. Please set AZURE_KEYVAULT_NAME environment variable")
	}

	certName := os.Getenv("AZURE_CERT_NAME")
	if certName == "" {
		log.Fatal("No certificate name specified. Please set AZURE_CERT_NAME environment variable")
	}

	pfxPassword := os.Getenv("PFX_PASSWORD") // Empty string if not set

	log.Printf("Starting certificate management for domains: %v", domains)
	log.Printf("Check interval: %v, Renewal threshold: %d days", checkInterval, renewBeforeDays)

	emailConfig := getEmailConfig()

	for {
		err := processCertificates(domains, email, keyVaultName, certName, pfxPassword, renewBeforeDays)
		if err != nil {
			log.Printf("Error processing certificates: %v", err)
			if emailConfig.Enabled {
				errorMessage := fmt.Sprintf("Error processing certificates for domains: %v\n\nError details:\n%v", domains, err)
				if notifyErr := sendErrorNotification(emailConfig, "Certificate Processing Error", errorMessage); notifyErr != nil {
					log.Printf("Failed to send error notification: %v", notifyErr)
				}
			}
		}

		log.Printf("Waiting %v before next check...", checkInterval)
		time.Sleep(checkInterval)
	}
}

func processCertificates(domains []string, email, keyVaultName, certName, pfxPassword string, renewBeforeDays int) error {
	// Check if certificate needs renewal
	needsRenewal, err := checkIfRenewalNeeded(keyVaultName, certName, renewBeforeDays)
	if err != nil {
		log.Printf("Error checking certificate renewal: %v", err)
	}

	if !needsRenewal {
		log.Printf("Certificate is still valid and not due for renewal")
		return nil
	}

	// Create a user
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("error generating private key: %v", err)
	}

	user := &User{
		Email: email,
		key:   privateKey,
	}

	config := lego.NewConfig(user)
	config.CADirURL = "https://acme-v02.api.letsencrypt.org/directory"

	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("error creating client: %v", err)
	}

	// Solve HTTP-01 challenge
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
	if err != nil {
		return fmt.Errorf("error setting up HTTP-01 provider: %v", err)
	}

	// Register user
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("error registering user: %v", err)
	}
	user.Registration = reg

	// Request certificate
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("error obtaining certificate: %v", err)
	}

	// Convert to PFX
	pfxData, err := convertToPFX(certificates.Certificate, certificates.PrivateKey, pfxPassword)
	if err != nil {
		return fmt.Errorf("error converting to PFX: %v", err)
	}

	// Upload to Azure Key Vault
	err = uploadToKeyVault(context.Background(), keyVaultName, certName, pfxData, pfxPassword)
	if err != nil {
		return fmt.Errorf("error uploading to Key Vault: %v", err)
	}

	log.Printf("Successfully processed certificates for domains: %v", domains)
	return nil
}

func checkIfRenewalNeeded(keyVaultName, certName string, renewBeforeDays int) (bool, error) {
	ctx := context.Background()
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return true, fmt.Errorf("failed to create credential: %v", err)
	}

	client, err := azcertificates.NewClient(
		fmt.Sprintf("https://%s.vault.azure.net/", keyVaultName),
		cred,
		nil,
	)
	if err != nil {
		return true, fmt.Errorf("failed to create client: %v", err)
	}

	cert, err := client.GetCertificate(ctx, certName, "", nil)
	if err != nil {
		return true, fmt.Errorf("failed to get certificate: %v", err)
	}

	if cert.Attributes == nil || cert.Attributes.Expires == nil {
		return true, fmt.Errorf("certificate attributes or expiration date is missing")
	}

	expiresOn := *cert.Attributes.Expires
	renewalDate := expiresOn.AddDate(0, 0, -renewBeforeDays)

	needsRenewal := time.Now().After(renewalDate)
	if needsRenewal {
		log.Printf("Certificate will expire on %v, renewal needed (threshold: %d days)", expiresOn, renewBeforeDays)
	} else {
		log.Printf("Certificate valid until %v (renewal threshold: %d days before expiration)", expiresOn, renewBeforeDays)
	}

	return needsRenewal, nil
}

func convertToPFX(certPEM, keyPEM []byte, password string) ([]byte, error) {
	// Decode private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS8 format as fallback
		key, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key: PKCS1: %v, PKCS8: %v", err, err2)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("parsed key is not RSA")
		}
	}

	// Decode certificates (leaf + intermediates)
	var certs []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}

	// First cert is the leaf, rest are CA chain
	leaf := certs[0]
	var caCerts []*x509.Certificate
	if len(certs) > 1 {
		caCerts = certs[1:]
	}

	pfxData, err := gopkcs12.Encode(rand.Reader, privateKey, leaf, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PFX: %v", err)
	}

	return pfxData, nil
}

func uploadToKeyVault(ctx context.Context, vaultName, certName string, pfxData []byte, password string) error {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to create credential: %v", err)
	}

	client, err := azcertificates.NewClient(
		fmt.Sprintf("https://%s.vault.azure.net/", vaultName),
		cred,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to create client: %v", err)
	}

	certString := base64.StdEncoding.EncodeToString(pfxData)
	_, err = client.ImportCertificate(ctx, certName, azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: &certString,
		Password:                 &password,
	}, nil)

	return err
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultValue
}
