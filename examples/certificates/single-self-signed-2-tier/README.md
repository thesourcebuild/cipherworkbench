# Single (Self-Signed | 2-Tier)

Certificate Studio generates a private Root CA and uses it to issue one server certificate.

```text
root-ca.crt + root-ca.key
  -> server.crt + private.key
  -> chain.pem
```

Run from the repository root:

```bash
npx tsx examples/certificates/single-self-signed-2-tier/run.ts
```
