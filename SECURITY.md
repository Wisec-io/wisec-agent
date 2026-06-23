# Security Policy

## Reporting a vulnerability

Please report security issues privately to **contact@wisec.io**. Do not open a
public issue for a suspected vulnerability.

Include enough detail to reproduce the issue (affected version, environment,
steps). We aim to acknowledge reports within a few business days and will keep
you informed of the remediation timeline. Please allow a reasonable period for a
fix before any public disclosure.

## Scope

This repository contains the CI/CD agent only. The agent signs build metadata
with a private key supplied through `AGENT_PRIVATE_KEY_HEX`; keep that key
confidential and store it as a protected CI variable.
