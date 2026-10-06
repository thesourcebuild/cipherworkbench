# Single (Self-Signed | Standalone)

This example generates one end-entity certificate whose Issuer equals its Subject.

```text
server.crt (self-signed)
private.key
```

Run from the repository root:

```bash
npx tsx examples/certificates/single-self-signed-standalone/run.ts
```

Run the generator before using the Python or shell helpers in this directory. The generated `server.crt` is its own trust anchor and contains only the TLS Web Server Authentication EKU.
