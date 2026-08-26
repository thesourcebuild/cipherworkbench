# Creating a Good Issue

Found a bug or have a feature request? Here is how to write a useful issue for
Cipher Workbench.

## Before posting

- Search the issue tracker for an existing issue first.
- Test against the latest version (the `version` file at the repo root is the
  single source of truth).
- Narrow the scope yourself: which tool family, algorithm, option, host (web/desktop), or OS platform? A report that isolates the problem is fixed quickly.

## The most useful thing you can paste

The **tool name**, **selected options/spec**, **input data representation**, and the **exact computed output vs expected output**. That single set of details allows reproducing your exact computation without guessing algorithm options by trial and error.

## Bug report template

```
### Description
What went wrong?

### Tool and Configuration
- Category / Tool: (e.g. Cipher > AES-256-GCM, Hash > SHA-256, KDF > Argon2id, CRC > CRC-32/ISO-HDLC)
- Selected Options: (e.g. Key length, IV/Nonce, Salt, AAD, Output Encoding)
- Input format & content: (Text UTF-8, Hex, Base64, or File)
- Computed / Rendered output:
  <paste exact computed output or error message here>

### Expected behavior
What the output should have been (with reference test vectors or oracle outputs if available).

### Environment
- OS: Windows 11 / Ubuntu 24.04 / macOS ...
- Host: Web browser (name & version) or Desktop App (installed copy or dev build)
- Version: (from the `version` file at the repo root)

### Attachments (optional)
- A screenshot of the tool panel with the failing options.
- Diagnostic message and rule code (e.g. C001, H002) if the engine lint panel complained.
```

## Feature request template

```
### Problem / Need
What algorithm, encoding, parameter set, or UI capability is missing or inconvenient?

### Proposed solution
How would you like the tool or feature to behave?

### Algorithm or Standard Specifications
Reference RFCs, NIST standards, FELICS/NESSIE test vectors, or reference implementations.

### Alternatives considered
Any other approaches or workarounds you have considered.
```

## A good issue includes

- The **exact algorithm options** (e.g. key length, nonce size, cipher mode, padding)
- The **input representation** (UTF-8, Hex, Base64, raw bytes, or File)
- The **computed result or error message**, pasted verbatim
- Whether it occurs in **web, desktop, or both**
- For diagnostics: the **rule code** shown in the engine lint panel, so the fix can be targeted

Well-written issues get investigated and resolved faster.
