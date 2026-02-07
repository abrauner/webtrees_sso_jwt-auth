# Contributing to JWT Auth for Webtrees

Thank you for considering contributing to this project. This document provides guidelines for contributing to the JWT Authentication module for Webtrees.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)
- [Security](#security)

## Code of Conduct

This project adheres to the Contributor Covenant Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior by opening an issue.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Create a branch for your changes
4. Make your changes
5. Test your changes
6. Submit a pull request

## Development Setup

This module requires:
- PHP 8.3 or higher
- Composer
- Webtrees 2.1.x (installed automatically as a dev dependency)

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/jwt-auth.git
cd jwt-auth

# Install dependencies
composer install

# Run tests to verify setup
vendor/bin/phpunit
```

## Making Changes

### Branch Naming

Use descriptive branch names:
- `feature/add-new-algorithm-support`
- `fix/token-validation-bug`
- `docs/update-configuration-guide`

### Commit Messages

Write clear commit messages:
- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters
- Reference issues and pull requests when relevant

Examples:
```
Add support for ES384 algorithm

Fix token validation when JWKS cache expires

Update CONFIGURATION.md with new examples

Closes #123
```

### Code Changes

- Follow the existing code style (PSR-12)
- Add tests for new functionality
- Update documentation when needed
- Ensure all tests pass before submitting

## Testing

This project has comprehensive test coverage. All new features and bug fixes must include tests.

```bash
# Run all tests
vendor/bin/phpunit

# Run specific test file
vendor/bin/phpunit tests/JwtAuthModuleTest.php

# Run with coverage report
vendor/bin/phpunit --coverage-html coverage/
```

### Test Organization

Tests are organized by functionality:
- `JwtAuthModuleTest.php` - Middleware logic, token extraction, JWT validation (T01-T70)
- `JwtConfigPageTest.php` - Admin config page rendering (T49-T52)
- `JwtConfigActionTest.php` - Config validation and saving (T41-T48)

### Writing Tests

All tests extend `Fisharebest\Webtrees\TestCase` which provides:
- In-memory SQLite database
- Webtrees service container
- Request/response factories

Key conventions:
- Module DB name is `_jwt-auth_`
- Register module in DB: `DB::table('module')->insertOrIgnore(['module_name' => '_jwt-auth_', 'status' => 'enabled']);`
- Call `boot()` in `setUp()` to register routes
- Use `en-US` locale to avoid language file warnings

Example test structure:
```php
public function testNewFeature(): void
{
    // Register module in DB
    DB::table('module')->insertOrIgnore([
        'module_name' => '_jwt-auth_',
        'status' => 'enabled',
    ]);

    $module = new JwtAuthModule();
    $module->boot();

    // Test logic here

    self::assertSame($expected, $actual);
}
```

## Submitting Changes

1. Push your changes to your fork
2. Submit a pull request to the `main` branch
3. Clearly describe the problem and solution
4. Include the relevant issue number if applicable
5. Ensure all CI checks pass

### Pull Request Template

Your PR description should include:
- What changes were made
- Why the changes were needed
- How the changes were tested
- Any breaking changes or migration notes
- Related issues

## Coding Standards

This project follows PSR-12 coding standards with these conventions:

### PHP Style

- Constructor property promotion with `private readonly`
- Trailing commas in multi-line arrays and parameter lists
- Type declarations for all parameters and return values
- Strict types: `declare(strict_types=1);`

### Webtrees Integration

- Access services via `Registry::container()->get(ServiceClass::class)`
- Use `Validator::attributes($request)` for config.ini.php values
- Use module preferences via `$this->getPreference()`/`$this->setPreference()`
- Route authorization via `->extras(['middleware' => [AuthAdministrator::class]])`

### Documentation

- PHPDoc blocks for all public methods
- Inline comments for complex logic
- Update README.md and docs/ when adding features
- Keep CLAUDE.md in sync with architecture changes

## Security

### Reporting Security Issues

Do not open public issues for security vulnerabilities. Instead:
1. Email the maintainers (see README for contact info)
2. Describe the vulnerability in detail
3. Wait for a response before public disclosure

### Security Considerations

When contributing, be aware of:
- JWT validation security (algorithm confusion, none attack)
- Token extraction from headers/cookies
- Rate limiting bypass
- Authentication bypass scenarios
- JWKS URL validation (HTTPS only)
- Key strength requirements (HS256 minimum 32 chars)

See `docs/SECURITY.md` for detailed security model.

## Getting Help

- Check existing issues and pull requests
- Read the documentation in `docs/`
- Review the test suite for examples
- Ask questions in a new issue with the "question" label

## License

By contributing, you agree that your contributions will be licensed under the same GPL-3.0-or-later license that covers this project.
