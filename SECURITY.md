# Security Policy

## Reporting
Do not open a public issue containing credentials, customer information, invoices, account identifiers, or infrastructure details. Use a private disclosure channel maintained by the repository owner.

## Repository rules
- Never commit `.env`, cloud keys, Telegram tokens, provider databases, cache files, logs, browser cookies, session state, or production exports.
- Use least-privilege provider credentials.
- Rotate any credential that appears in a terminal transcript, issue, pull request, commit, artifact, or chat.
- Run `scripts/secret-scan.sh` before each public push and enable GitHub secret scanning/push protection.

## Collector boundary
Portal credentials and browser sessions belong on the isolated collector. The dashboard should receive only normalized billing/invoice data over an authenticated channel.
