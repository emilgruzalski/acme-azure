# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2025-04-13
### Added
- Optional email notifications for error events
- SMTP configuration support
- Detailed error reporting in email notifications
- Default email configuration based on Let's Encrypt contact email

## [1.1.0] - 2025-04-13
### Added
- PFX password support through PFX_PASSWORD environment variable
- Configurable renewal threshold through RENEW_BEFORE_DAYS environment variable (default: 30 days)
- Configurable check interval through CHECK_INTERVAL environment variable (default: 24h)
- Automatic certificate expiration checking
- Smart renewal that only requests new certificates when needed

## [1.0.0] - 2025-04-13
### Added
- Initial release
- Automatic certificate generation using Let's Encrypt
- Support for multiple domains in a single certificate
- HTTP-01 challenge verification
- Automatic PFX conversion
- Azure Key Vault integration
- Continuous certificate monitoring and renewal
- Docker support
- Azure Container Apps deployment support
