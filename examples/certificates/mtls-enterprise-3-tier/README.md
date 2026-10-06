# mTLS Enterprise (3-Tier)

This example generates an offline Root CA, an operational Intermediate CA, and separate server and client identities.

```text
ca.crt + ca.key
  -> intermediate.crt + intermediate.key
     -> server.crt + server.key
     -> client.crt + client.key + client.p12
```

Run from the repository root:

```bash
npx tsx examples/certificates/mtls-enterprise-3-tier/run.ts
```

The existing Python and shell helpers in this directory provide interactive enterprise mutual-TLS handshake tests.
