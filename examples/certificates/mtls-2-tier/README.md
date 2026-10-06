# mTLS (2-Tier)

This example generates one Root CA plus separate server and client identities.

```text
ca.crt + ca.key
  -> server.crt + server.key
  -> client.crt + client.key + client.p12
```

Run from the repository root:

```bash
npx tsx examples/certificates/mtls-2-tier/run.ts
```

The existing Python and shell helpers in this directory provide interactive mutual-TLS handshake tests.
