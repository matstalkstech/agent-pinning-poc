# Security Policy

## Overview

The Agent Goal Binding project is a research proof-of-concept focused on cryptographic goal-binding for AI agents. Security is a core aspect of this project, and we take vulnerability reports seriously.

## Supported Versions

| Version | Support Status |
|---------|---------------|
| 0.1.x   | ✅ Active development (POC/Alpha) |

**Note:** This is an alpha research POC. Production deployment is not recommended until security audits are completed.

## Reporting a Vulnerability

### Private Disclosure

If you discover a security vulnerability, please report raise a PR or an Issue detailing the finding. There are no bounties paid, this is an experiment.

**What to include:**
- Description of the vulnerability
- Steps to reproduce the issue
- Affected versions and components
- Potential impact assessment
- Suggested fix (if available)

### Response Timeline

- **Initial Response:** Within 72 hours
- **Vulnerability Assessment:** Within 7 days
- **Security Patch:** Within 30 days for critical issues
- **Public Disclosure:** After patch is released or 90 days (whichever comes first)

### Security Advisory Process

1. We will acknowledge receipt of your report
2. We will investigate and assess severity
3. We will develop and test a fix
4. We will release a security patch
5. We will publish a security advisory with credit to the reporter (if desired)

## Security Best Practices

### GPG Key Management

This project relies on Ed25519 GPG keys for cryptographic signing. Follow these best practices:

#### Key Generation
```bash
# Generate a secure Ed25519 key
gpg --quick-generate-key "Your Name <email@example.com>" ed25519 sign 2y

# Use a strong passphrase (16+ characters, mixed case, numbers, symbols)
```

#### Key Storage
- **Private Keys:** Store in encrypted storage, never commit to version control
- **Backup:** Keep encrypted backups in secure locations
- **Rotation:** Rotate keys at least annually
- **Revocation:** Prepare revocation certificates in advance

#### Key Distribution
- **Public Keys:** Distribute via keyservers or project repository
- **Fingerprints:** Verify key fingerprints through multiple channels
- **Trust:** Use GPG's web of trust for key verification

### Certificate Security

#### Manifest Signing
```bash
# Always verify manifest before signing
cat config/agent_manifest.json | jq .

# Sign with your private key
agent-sign config/agent_manifest.json <YOUR_KEY_ID>

# Verify the signature
gpg --verify config/agent_certificate.asc
```

#### Certificate Validation
- Always validate certificates before loading into auth service
- Check certificate expiration dates
- Verify signer identity matches expected developer
- Monitor for certificate tampering attempts

### Deployment Security

#### Auth Service
- Run auth service in isolated environment
- Use TLS/HTTPS for all network communication (not implemented in POC)
- Implement rate limiting to prevent DoS attacks
- Monitor logs for suspicious authorization attempts
- Rotate decision log merkle chains periodically

#### Agent Runtime
- Run agents with minimal privileges
- Implement network segmentation
- Monitor for anomalous behavior patterns
- Log all privileged actions for audit

### Security Testing

For comprehensive security testing procedures, see [docs/SECURITY_TESTING.md](docs/SECURITY_TESTING.md).

**Key testing areas:**
- Prompt injection resistance
- Goal tampering detection
- Permission escalation prevention
- Cryptographic signature validation
- Multi-turn adaptive attacks

#### Running Security Tests
```bash
# Start auth service
agent-auth-server --cert config/agent_certificate.asc

# Run security test suite
pytest tests/security/ -v

# Run garak security probes
pytest tests/security/test_garak_probes.py -v

# Run PurpleLlama CyberSecEval tests
pytest tests/security/test_purplellama.py -v
```

## Known Limitations

This POC has intentional limitations that should be understood before deployment:

### Cryptographic Scope
- **What's Protected:** Agent goals and permissions integrity
- **What's NOT Protected:**
  - In-transit data (no TLS implementation)
  - At-rest data encryption
  - Agent memory/state confidentiality
  - Side-channel attacks

### Threat Model
- **Mitigated:** Prompt injection leading to goal/permission tampering
- **NOT Mitigated:**
  - DoS attacks on auth service
  - Physical access to signing keys
  - Compromised GPG keyring
  - Time-of-check-to-time-of-use (TOCTOU) races
  - Social engineering attacks on developers

### Operational Limitations
- Single-agent design (no multi-agent coordination)
- Manual key management (no automated rotation)
- Local-only auth service (no distributed deployment)
- Synchronous verification (no async/batch optimization)

## Security Assumptions

This project assumes:

1. **GPG Implementation:** The GPG binary is trustworthy and not compromised
2. **Key Security:** Private signing keys are stored securely
3. **Network:** Local communication channel is trusted (localhost)
4. **Host Security:** The host system is not compromised
5. **Developer Trust:** The manifest signer is authorized and trustworthy

## Vulnerability Severity Levels

| Severity | Definition | Response Time |
|----------|-----------|---------------|
| **Critical** | Allows goal/permission bypass without detection | 48 hours |
| **High** | Enables privilege escalation or signature forgery | 7 days |
| **Medium** | Causes incorrect authorization decisions | 30 days |
| **Low** | Minor issues with limited security impact | 90 days |

## Security Updates

Security updates will be published via:
- GitHub Security Advisories
- Git tags with security patch notes
- CHANGELOG.md with [SECURITY] prefix
- Email notification to security mailing list (future)

## Acknowledgments

We appreciate responsible disclosure and will credit security researchers who report vulnerabilities (unless they prefer to remain anonymous).

## Contact

For security concerns:
- **GitHub:** https://github.com/matstalktech/agent-goal-binding/security/advisories/new
- **GitHub Issues:** For non-security bugs only (do not report security issues publicly)

For general questions, see [CONTRIBUTING.md](CONTRIBUTING.md).

## References

- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [AI Risk Database](https://airisk.io/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [Garak LLM Vulnerability Scanner](https://github.com/leondz/garak)
- [Meta PurpleLlama CyberSecEval](https://github.com/meta-llama/PurpleLlama)
