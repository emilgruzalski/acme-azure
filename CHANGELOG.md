# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-11
### Changed
- Replaced OpenSSL subprocess with native Go PKCS12 library (`go-pkcs12`) for PFX conversion
- Multi-stage Docker build with `distroless/static:nonroot` base image (~20 MB, down from ~1.2 GB)
- Container runs as `nonroot` user instead of root
- ACME account registered once at startup instead of on every renewal cycle
- Azure credential and Key Vault client created once and reused across cycles
- Replaced `time.Sleep` loop with `time.Ticker` and `select` for signal handling
- Split single `main.go` into `main.go`, `acme.go`, `azure.go`, `notify.go`
- Application entry point uses `run() error` pattern
- Error wrapping uses `%w` verb for `errors.Is()`/`errors.As()` support
- Configuration loaded into a single `config` struct via `loadConfig()`

### Added
- Permanent HTTP server on port 80 with `/healthz` health check endpoint
- Custom `challengeProvider` implementing both `challenge.Provider` and `http.Handler`
- Graceful shutdown on SIGINT/SIGTERM with 5s timeout
- `.dockerignore` to reduce Docker build context

### Removed
- OpenSSL system dependency
- Temporary certificate files on disk during PFX conversion
- `github.com/go-acme/lego/v4/challenge/http01` dependency (replaced by custom provider)

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
