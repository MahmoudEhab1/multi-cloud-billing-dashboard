# Provider extension interface

A new provider should map its native billing model to the dashboard metrics `kpis`, `services`, `trend`, `daily`, `resources`, `invoices`, and `enhanced_kpis`.

Prefer an official provider API with read-only billing permissions. Use an external collector only when a suitable API is unavailable. A collector should send only the minimum normalized billing fields needed by the dashboard and authenticate each push with an independent secret.
