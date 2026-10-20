# Security Policy

`libnunchuk` is a Bitcoin multisig library used by the [Nunchuk](https://nunchuk.io) desktop and mobile wallets. It handles keys, descriptors, PSBTs, and related wallet logic — software that can affect users’ funds. Please report security issues privately so we can fix them before public disclosure.

## Reporting a Vulnerability

**Do not** open a public GitHub issue, pull request, or discussion for suspected security vulnerabilities.

Please email: **security@nunchuk.io**

Use a clear subject line, for example: `[SECURITY] libnunchuk: <short summary>`.

Include as much of the following as you can:

- Description of the issue and its security impact
- Affected version, commit, or branch (e.g. `main`, `main-qt`)
- Steps to reproduce, or a minimal proof of concept
- Suggested fix, if you have one

We will acknowledge receipt as soon as practical and keep you informed of progress. Please give us a reasonable window to investigate and ship a fix before any public disclosure.

This address is for **security reports only**, not general product support. For support, use the contact options on [nunchuk.io](https://nunchuk.io).

## Scope

In scope for this repository:

- Cryptographic misuse, key/mnemonic leakage, or unsafe signing flows
- Transaction construction bugs that can lose or misdirect funds
- Authentication / TLS / coordination-channel issues in library code
- Remote or local privilege issues that expose wallet secrets

Out of scope (report elsewhere or treat as non-security unless they enable fund loss):

- Issues only in third-party code under `contrib/` that are already fixed upstream (prefer reporting upstream; we will still track updates)
- Pure DoS / crash bugs with no confidentiality or integrity impact, unless they block recovery of funds
- Social engineering, phishing, or physical attacks on devices
- Theoretical issues without a plausible exploit path

## Supported Versions

Security fixes are applied to the actively maintained branches used by Nunchuk apps (typically `main` / `main-qt` and current release tags). Older tags may not receive backports unless a fix is critical.

## Safe Harbor

We welcome good-faith security research. If you follow this policy, avoid privacy violations and destruction of data, and do not exploit issues beyond what is needed to demonstrate the vulnerability, we will not pursue legal action related to your report.
