package main

import (
	"fmt"
	"log"
	"net/smtp"
	"os"
)

type emailConfig struct {
	Enabled   bool
	SMTPHost  string
	SMTPPort  string
	Username  string
	Password  string
	FromEmail string
	ToEmail   string
}

func loadEmailConfig() emailConfig {
	return emailConfig{
		Enabled:   os.Getenv("NOTIFY_EMAIL_ENABLED") == "true",
		SMTPHost:  os.Getenv("SMTP_HOST"),
		SMTPPort:  envWithDefault("SMTP_PORT", "587"),
		Username:  os.Getenv("SMTP_USERNAME"),
		Password:  os.Getenv("SMTP_PASSWORD"),
		FromEmail: envWithDefault("SMTP_FROM", os.Getenv("EMAIL")),
		ToEmail:   envWithDefault("SMTP_TO", os.Getenv("EMAIL")),
	}
}

func sendErrorNotification(cfg emailConfig, subject, message string) error {
	if !cfg.Enabled {
		return nil
	}

	if cfg.SMTPHost == "" || cfg.Username == "" || cfg.Password == "" {
		return fmt.Errorf("incomplete SMTP configuration")
	}

	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPHost)

	body := fmt.Sprintf("Subject: %s\r\n"+
		"From: %s\r\n"+
		"To: %s\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", subject, cfg.FromEmail, cfg.ToEmail, message)

	err := smtp.SendMail(
		cfg.SMTPHost+":"+cfg.SMTPPort,
		auth,
		cfg.FromEmail,
		[]string{cfg.ToEmail},
		[]byte(body),
	)
	if err != nil {
		return fmt.Errorf("sending notification email: %w", err)
	}

	log.Printf("Notification email sent successfully to %s", cfg.ToEmail)
	return nil
}
