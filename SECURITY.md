# Security policy

Set `HR_ENV=production` and a unique `HR_SECRET_KEY` of at least 32 characters
through the hosting provider's secret manager. For a new production database,
also set `HR_BOOTSTRAP_ADMIN_EMAIL`, `HR_BOOTSTRAP_ADMIN_PASSWORD`, and
optionally `HR_BOOTSTRAP_ADMIN_NAME`; the first start creates one protected
administrator and does not seed demo identities. Remove the bootstrap password
after first login. Keep SQLite, uploaded employee documents, SMTP credentials,
and backups on protected persistent storage, and use HTTPS.

Do not report credentials, employee records, reset tokens, or working exploits
in a public issue. Contact the repository owner privately with the affected
version and reproduction steps.
