# Certificate Studio Examples

These examples mirror the seven Certificate Studio members exactly. Every `run.ts` executes the real `cert-creator` tool and writes the same filenames shown by the Studio workflow badges and commands.

| # | Studio member | Example directory | Trust path |
|---|---|---|---|
| 1 | Single (Self-Signed \| Standalone) | [`single-self-signed-standalone/`](single-self-signed-standalone/) | Server certificate signs itself |
| 2 | Single (Self-Signed \| 2-Tier) | [`single-self-signed-2-tier/`](single-self-signed-2-tier/) | Generated Root CA -> Server |
| 3 | Single (Self-Signed \| 3-Tier) | [`single-self-signed-3-tier/`](single-self-signed-3-tier/) | Generated Root CA -> Intermediate CA -> Server |
| 4 | Single (CA-Signed \| 2-Tier) | [`single-ca-signed-2-tier/`](single-ca-signed-2-tier/) | Supplied Root CA -> Server |
| 5 | Single (CA-Signed \| 3-Tier) | [`single-ca-signed-3-tier/`](single-ca-signed-3-tier/) | Supplied Root CA -> Supplied Intermediate CA -> Server |
| 6 | mTLS (2-Tier) | [`mtls-2-tier/`](mtls-2-tier/) | Root CA -> Server + Client |
| 7 | mTLS Enterprise (3-Tier) | [`mtls-enterprise-3-tier/`](mtls-enterprise-3-tier/) | Root CA -> Intermediate CA -> Server + Client |

## Run An Example

From the repository root:

```bash
npx tsx examples/certificates/single-self-signed-standalone/run.ts
npx tsx examples/certificates/single-self-signed-2-tier/run.ts
npx tsx examples/certificates/single-self-signed-3-tier/run.ts
npx tsx examples/certificates/single-ca-signed-2-tier/run.ts
npx tsx examples/certificates/single-ca-signed-3-tier/run.ts
npx tsx examples/certificates/mtls-2-tier/run.ts
npx tsx examples/certificates/mtls-enterprise-3-tier/run.ts
```

The CA-signed examples first create external issuer fixtures, then supply those credentials to Certificate Studio. The tool itself does not generate their CA hierarchy.

## Tests

```bash
pnpm exec vitest run tests/certificate-examples.test.ts
```

The tests generate every flow, verify required artifacts and command filenames, parse each certificate, and validate every Subject/Issuer trust link.

The root-level `verify_mock_tls.ts`, `verify_mock_mtls.ts`, and `verify_pki_crl_and_keys.ts` scripts remain available for live OpenSSL integration checks.
