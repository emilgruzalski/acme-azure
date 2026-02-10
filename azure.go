package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

func checkIfRenewalNeeded(ctx context.Context, client *azcertificates.Client, certName string, renewBeforeDays int) (bool, error) {
	cert, err := client.GetCertificate(ctx, certName, "", nil)
	if err != nil {
		return true, fmt.Errorf("getting certificate: %w", err)
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
			return nil, fmt.Errorf("parsing private key: PKCS1: %w, PKCS8: %w", err, err2)
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
			return nil, fmt.Errorf("parsing certificate: %w", err)
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
		return nil, fmt.Errorf("encoding PFX: %w", err)
	}

	return pfxData, nil
}

func uploadToKeyVault(ctx context.Context, client *azcertificates.Client, certName string, pfxData []byte, password string) error {
	certString := base64.StdEncoding.EncodeToString(pfxData)
	_, err := client.ImportCertificate(ctx, certName, azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: &certString,
		Password:                 &password,
	}, nil)
	if err != nil {
		return fmt.Errorf("importing certificate: %w", err)
	}
	return nil
}
