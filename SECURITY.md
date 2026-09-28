# Security Policy

## Supported versions

Security fixes land on the latest released minor version of `email-deliverability-suite`.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please do not open a public issue for security problems.

Email **security@example.com** <!-- TODO(maintainer): replace with the real security contact address before publishing --> with:

- a description of the issue and its impact,
- the `deliv` version (`deliv --version`) and Python version,
- steps or a minimal input file that reproduces it (use fictional domains and addresses only).

You should get an acknowledgement within 5 business days. Once a fix is ready, we will coordinate a
release and credit you in the changelog unless you prefer to stay anonymous.

## Scope notes

`deliv` performs DNS queries, DNSBL lookups, and one HTTPS fetch (the MTA-STS policy file). It never
sends email, never uploads the files you scan, and has no telemetry. Reports about those network paths
(for example, DNS response parsing that could be abused by a hostile nameserver, or unsafe handling of
untrusted `.eml` / HTML input) are in scope.
