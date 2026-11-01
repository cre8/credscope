# Security policy

Credscope checks documents that carry personal data and keys, so a flaw in what it reports, e.g. a signature shown as
valid that is not, matters. Please report it privately, not in a public issue or pull request.

## Reporting a vulnerability

Report it through [GitHub private vulnerability reporting](https://github.com/cre8/credscope/security/advisories/new),
with:

- what is affected: the page, the command, or the check
- the steps or the document that show it, with throwaway keys
- the version or commit

Flaws in the packages of identity-common-ts, which do most of the parsing and
validation, belong to [its security policy](https://github.com/openwallet-foundation-labs/identity-common-ts/security/policy).

## Supported versions

Only the latest release and `main`, which the web pages are built from, get fixes.
