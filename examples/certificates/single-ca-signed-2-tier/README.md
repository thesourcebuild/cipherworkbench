# Single (CA-Signed | 2-Tier)

This example creates an external Root CA fixture, supplies `ca.crt` and `ca.key` to Certificate Studio, and generates only the new server certificate.

```text
supplied ca.crt + ca.key
  -> server.crt + private.key
  -> chain.pem
```

Run from the repository root:

```bash
npx tsx examples/certificates/single-ca-signed-2-tier/run.ts
```
