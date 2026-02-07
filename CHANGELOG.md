# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial open-source release preparation
- Community health files (CONTRIBUTING.md, CODE_OF_CONDUCT.md, CODEOWNERS)
- Issue templates for bugs, feature requests, and questions
- Pull request template
- Comprehensive documentation structure

## [1.0.0] - TBD

### Added
- JWT authentication middleware for Webtrees 2.1.x
- Support for RS256, HS256, and ES256 algorithms
- JWKS URL integration with automatic key rotation
- Token extraction from HTTP headers and cookies
- Configurable token source priority (header-first or cookie-first)
- Admin configuration interface
- Rate limiting (20 attempts per 60 seconds)
- Config.ini.php override support for secure credential management
- Comprehensive test suite (85 tests)
- Security validations:
  - HTTPS-only JWKS URLs
  - Private key rejection
  - HS256 minimum key length enforcement
  - Algorithm confusion attack prevention
  - None algorithm rejection
- Documentation:
  - README.md with installation and usage instructions
  - docs/ARCHITECTURE.md with module lifecycle details
  - docs/CONFIGURATION.md with all settings reference
  - docs/SECURITY.md with security model and recommendations

### Security
- JWT signature validation via firebase/php-jwt
- Token expiration (exp) and not-before (nbf) enforcement
- Issuer (iss) and audience (aud) claim validation
- Email claim requirement for user matching
- Account status verification (email verified + approved)
- Authentication failure logging
- Rate limiting to prevent brute force attacks
- JWKS keyset caching with 1-hour TTL
- Config.ini.php support to avoid storing secrets in database

### Technical
- PHP 8.3+ requirement
- PSR-15 middleware implementation
- PSR-12 coding standards
- Automated release workflow via GitHub Actions
- Comprehensive test coverage with in-memory SQLite database

---

## Release Template

Use this template for new releases:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes in existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security-related changes
```

[Unreleased]: https://github.com/abrauner/webtrees-jwt-auth/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/abrauner/webtrees-jwt-auth/releases/tag/v1.0.0
