# Security Policy

## Supported versions

acme-proxy is in early development. Only the latest release receives security
fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report them privately through GitHub: open the **Security** tab of this
repository and select **Report a vulnerability**. Include, if you can:

- a description of the issue and its impact;
- the steps or a minimal configuration to reproduce it;
- the affected version or commit.

## What to expect

This project is maintained by one person in their spare time. I aim to
acknowledge reports within 7 days and to keep you informed until the issue is
resolved. With your permission, you will be credited in the release notes.

## Scope

In scope, for example:

- bypassing authentication or the per-client source address binding;
- publishing or deleting records for names a client is not allowed to use;
- writing DNS records other than `_acme-challenge` TXT records;
- disclosure of the DNS provider token or of client tokens;
- crashes or resource exhaustion triggered by unauthenticated requests.

Out of scope:

- a compromised host running acme-proxy (see the security model in the README);
- insecure configurations, such as overly broad `sources` prefixes;
- vulnerabilities in the DNS provider or in ACME clients.