# Security Policy

CloudLeak Sentinel is a defensive credential-exposure monitoring prototype.

## Scope and safe use

Use it only on repositories, files, images, packages, pages, feeds, and accounts that you own or are explicitly authorized to assess. The project does not authenticate with, validate, redeem, rotate, or otherwise use discovered credentials.

Persisted findings contain masked values and SHA-256 fingerprints rather than plaintext secrets. Demo and benchmark content is synthetic and intentionally non-functional.

## Reporting a security issue

Do not publish real credentials in a public issue. Remove or rotate the credential first, then report the software issue without including the secret value.
