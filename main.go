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
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

type User struct {
	Email        string
	Registration *registration.Resource
	key          *rsa.PrivateKey
}

func (u *User) GetEmail() string                        { return u.Email }
func (u *User) GetRegistration() *registration.Resource { return u.Registration }
func (u *User) GetPrivateKey() crypto.PrivateKey        { return u.key }

// challengeProvider implements lego's challenge.Provider interface
// and http.Handler to serve ACME HTTP-01 tokens via the built-in HTTP server.
type challengeProvider struct {
	mu     sync.RWMutex
	tokens map[string]string
}

func (p *challengeProvider) Present(domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokens[token] = keyAuth
	return nil
}

func (p *challengeProvider) CleanUp(domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.tokens, token)
	return nil
}

func (p *challengeProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	p.mu.RLock()
	keyAuth, ok := p.tokens[token]
	p.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write([]byte(keyAuth))
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
		FromEmail: getEnvWithDefault("SMTP_FROM", os.Getenv("EMAIL")),
		ToEmail:   getEnvWithDefault("SMTP_TO", os.Getenv("EMAIL")),
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

	pfxPassword := os.Getenv("PFX_PASSWORD")

	// Graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Azure Key Vault client (created once)
	azCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("Failed to create Azure credential: %v", err)
	}

	kvClient, err := azcertificates.NewClient(
		fmt.Sprintf("https://%s.vault.azure.net/", keyVaultName),
		azCred,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create Key Vault client: %v", err)
	}

	// ACME account (registered once)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate ACME account key: %v", err)
	}

	user := &User{Email: email, key: privateKey}

	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = "https://acme-v02.api.letsencrypt.org/directory"

	challenge := &challengeProvider{tokens: make(map[string]string)}

	legoClient, err := lego.NewClient(legoConfig)
	if err != nil {
		log.Fatalf("Failed to create ACME client: %v", err)
	}

	if err := legoClient.Challenge.SetHTTP01Provider(challenge); err != nil {
		log.Fatalf("Failed to set HTTP-01 provider: %v", err)
	}

	reg, err := legoClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatalf("Failed to register ACME account: %v", err)
	}
	user.Registration = reg
	log.Printf("ACME account registered for %s", email)

	// HTTP server for health checks and ACME challenges
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.Handle("/.well-known/acme-challenge/", challenge)

	server := &http.Server{Addr: ":80", Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()
	log.Printf("HTTP server started on :80")

	log.Printf("Starting certificate management for domains: %v", domains)
	log.Printf("Check interval: %v, Renewal threshold: %d days", checkInterval, renewBeforeDays)

	emailConfig := getEmailConfig()

	runCheck := func() {
		err := processCertificates(ctx, legoClient, kvClient, domains, certName, pfxPassword, renewBeforeDays)
		if err != nil {
			log.Printf("Error processing certificates: %v", err)
			if emailConfig.Enabled {
				errorMessage := fmt.Sprintf("Error processing certificates for domains: %v\n\nError details:\n%v", domains, err)
				if notifyErr := sendErrorNotification(emailConfig, "Certificate Processing Error", errorMessage); notifyErr != nil {
					log.Printf("Failed to send error notification: %v", notifyErr)
				}
			}
		}
	}

	// Run first check immediately
	runCheck()

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down...")
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			server.Shutdown(shutdownCtx)
			return
		case <-ticker.C:
			runCheck()
		}
	}
}

func processCertificates(ctx context.Context, legoClient *lego.Client, kvClient *azcertificates.Client, domains []string, certName, pfxPassword string, renewBeforeDays int) error {
	needsRenewal, err := checkIfRenewalNeeded(ctx, kvClient, certName, renewBeforeDays)
	if err != nil {
		log.Printf("Error checking certificate renewal: %v", err)
	}

	if !needsRenewal {
		log.Printf("Certificate is still valid and not due for renewal")
		return nil
	}

	certificates, err := legoClient.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		return fmt.Errorf("error obtaining certificate: %v", err)
	}

	pfxData, err := convertToPFX(certificates.Certificate, certificates.PrivateKey, pfxPassword)
	if err != nil {
		return fmt.Errorf("error converting to PFX: %v", err)
	}

	err = uploadToKeyVault(ctx, kvClient, certName, pfxData, pfxPassword)
	if err != nil {
		return fmt.Errorf("error uploading to Key Vault: %v", err)
	}

	log.Printf("Successfully processed certificates for domains: %v", domains)
	return nil
}

func checkIfRenewalNeeded(ctx context.Context, client *azcertificates.Client, certName string, renewBeforeDays int) (bool, error) {
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
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
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

func uploadToKeyVault(ctx context.Context, client *azcertificates.Client, certName string, pfxData []byte, password string) error {
	certString := base64.StdEncoding.EncodeToString(pfxData)
	_, err := client.ImportCertificate(ctx, certName, azcertificates.ImportCertificateParameters{
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
