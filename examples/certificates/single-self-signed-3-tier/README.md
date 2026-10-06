# Single (Self-Signed | 3-Tier)

Certificate Studio generates the complete private hierarchy and one server certificate.

```text
root-ca.crt + root-ca.key
  -> intermediate.crt + intermediate.key
     -> server.crt + private.key
```

Run from the repository root:

```bash
npx tsx examples/certificates/single-self-signed-3-tier/run.ts
```

`server-chain.pem` contains the server certificate and Intermediate CA. `chain.pem` contains the server certificate, Intermediate CA, and Root CA.
