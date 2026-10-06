# Single (CA-Signed | 3-Tier)

This example creates an external Root and Intermediate CA fixture, supplies those credentials to Certificate Studio, and generates only the new server certificate.

```text
supplied root-ca.crt
  -> supplied intermediate.crt + intermediate.key
     -> server.crt + private.key
```

Run from the repository root:

```bash
npx tsx examples/certificates/single-ca-signed-3-tier/run.ts
```

The Root CA private key is not provided to Certificate Studio because the Intermediate CA signs the server certificate.
