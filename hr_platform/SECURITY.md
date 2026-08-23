# Security and deployment checklist

## Local development

1. Keep the server bound to `127.0.0.1` and use the launcher or `python3 server.py`.
2. Treat the seeded demo accounts as local fixtures only. Change their passwords or remove them before sharing a database or exposing the service.
3. Keep `hr_platform/data/hr.sqlite3`, uploaded files, `.env`, and backups outside source control.

## Production minimums

1. Set `HR_ENV=production` and a unique `HR_SECRET_KEY` of at least 32 characters through the process environment or a secret manager. The server refuses production startup without it. The checked-in `.env.example` is a reference only; this dependency-free server does not load `.env` automatically.
2. Put the application behind an HTTPS reverse proxy, restrict network access, and configure secure backup/restore procedures for SQLite and uploaded documents.
3. Configure SMTP with a dedicated service account, least privilege, TLS, and a sender address approved by the organization. Never put SMTP credentials in Git.
4. Disable or rotate all demo users, provision named accounts, enforce strong passwords, and review role permissions before go-live.
5. Review UAE legal, privacy, retention, and data-residency requirements with the organization’s legal/security owners. This application is not a substitute for that review.

## Reporting a vulnerability

Do not open a public issue containing credentials, employee data, tokens, or a working exploit. Contact the repository owner privately, include the affected version and reproduction steps, and allow time for remediation before public disclosure.
