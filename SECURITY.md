# Security policy

Cryptonite is a cryptographic library, so we take vulnerability reports
seriously and ask that they be reported privately.

## How to report a vulnerability

**Do not open a public issue for vulnerabilities.**

Use GitHub's private channel: the **Security → Report a vulnerability** tab
(private security advisories). If that is not available, contact the
repository maintainer directly (the contact is in the repository owner's
profile).

A report should ideally include:

- the module and function (for example, the `cert_decode`, `pkcs12_decode`
  decoder);
- the version/commit, platform, compiler;
- the input needed to reproduce it (for decoders, the DER byte blob);
- the impact (crash, out-of-bounds read/write, memory leak, incorrect result
  of a crypto operation).

## What is especially valuable

- Parsing of **untrusted input**: the ASN.1/DER decoders for certificates,
  CRLs, CMS, OCSP/TSP, PKCS#12 containers (see the harnesses in `fuzz/`).
- Memory-safety bugs (detected by ASan/UBSan in CI).
- Flaws that affect the correctness of signing/encryption.

## Scope

The project implements Ukrainian cryptographic standards. Note that the
validity of the state cryptographic-protection certification and the
regulatory status of individual algorithms are out of scope for this
repository; this is about software defects.
