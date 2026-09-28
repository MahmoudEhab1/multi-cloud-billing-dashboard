# Privacy and compliance publication guardrails

This portfolio repository is designed around **data minimization**: no real customer, employee, account, billing, contact, infrastructure, session, or credential data should be present.

Before publication, the repository owner should complete an organizational review covering applicable confidentiality obligations, employment/IP ownership, customer contracts/NDAs, Saudi Personal Data Protection Law (PDPL) obligations where relevant, and other privacy regimes that may apply to the organization or its customers (for example GDPR). This document is an engineering publication checklist, not legal advice.

## Never publish

- Names, emails, phone numbers, addresses, or other identifying information.
- Real cloud account IDs, tenancy identifiers, subscription IDs, invoice numbers, or billing amounts.
- Public/private production IP addresses, hostnames, internal paths that identify the organization, or admin URLs.
- API keys, access keys, private keys, shared secrets, passwords, password hashes, Telegram tokens/chat IDs, cookies, OTPs, or browser profiles.
- Production SQLite databases, cache files, logs, backups, screenshots, exports, PDFs, CSVs, or support transcripts.

## Public-fixture rule

All examples must be synthetic. Use reserved documentation IP ranges and `example.com` if an address is necessary.

## Publication process

1. Export only the cleaned source tree into a fresh directory.
2. Start a new Git history; never publish production repository history.
3. Run automated secret scanning and manual identifier review.
4. Obtain source-code ownership/open-publication approval.
5. Review third-party dependency licenses.
6. Enable repository secret scanning and push protection.
7. Re-run the review for every release artifact and screenshot.
