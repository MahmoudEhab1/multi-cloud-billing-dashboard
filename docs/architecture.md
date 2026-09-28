# Architecture

The web application owns normalization, caching, provider presentation, admin management, invoice rendering, and reporting. API-backed providers are queried directly. Portal-backed providers are isolated behind collectors so web-session credentials do not cross into the dashboard host.

The SQLite provider registry stores metadata and encrypted credentials; runtime data belongs in ignored cache/database paths rather than source control.
