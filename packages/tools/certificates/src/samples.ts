import type { ToolSample } from "@ocs/engine";

export const RSA_CERTIFICATE_PEM = `-----BEGIN CERTIFICATE-----
MIIERzCCAy+gAwIBAgIUEFfdhlDSCV1zqlRElBHJiJIuj0cwDQYJKoZIhvcNAQEL
BQAwgYIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQH
DA1TYW4gRnJhbmNpc2NvMRkwFwYDVQQKDBBDaXBoZXIgV29ya2JlbmNoMREwDwYD
VQQLDAhTZWN1cml0eTEYMBYGA1UEAwwPd29ya2JlbmNoLmxvY2FsMB4XDTI2MDky
MTIwMzMxNVoXDTM2MDkxODIwMzMxNVowgYIxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
DApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRkwFwYDVQQKDBBD
aXBoZXIgV29ya2JlbmNoMREwDwYDVQQLDAhTZWN1cml0eTEYMBYGA1UEAwwPd29y
a2JlbmNoLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmM0f
nJQvPvEcm8owyb9+tXcdKgUsjm2rcBK9bbr8wIis2mbbQtT6dc3qbTC4n5xIz5E8
506BcbsU5zeWyD2Jlzij74o7teiLL2dakpqYMGZSkeORg7zfiw9pEa4S3D/53z+h
2K04IkZEUW0GLzHiyfjQgqsOeWyetS7Sn5SecURz25ylAHWmLg8CTXEPvYXhI9QM
s5qZ3HPz+nEi/erbBiZMto1LbxksVqs3gsIf5lFMxBeyq1oCn6uU5ByDyovyKhGs
v0VFC0t0YWSYovQ6Al2QY2rFt0fDvtg/eJdjyQFZNCOwSDomAl3CdoosMlKrSbvt
Fc2wVwLS+yohYSK4gwIDAQABo4GyMIGvMB0GA1UdDgQWBBRS49WQt5UkUxbEeeQp
ccqpdojfCDAfBgNVHSMEGDAWgBRS49WQt5UkUxbEeeQpccqpdojfCDAzBgNVHREE
LDAqgg93b3JrYmVuY2gubG9jYWyCESoud29ya2JlbmNoLmxvY2FshwR/AAABMAwG
A1UdEwEB/wQCMAAwCwYDVR0PBAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEAK+NkF1+p9hNu2L5jz24J1pGIoa+b
Kgc1qIR6C0bxocdFi1krXmt0u+P4ze1KaKwuBsIxKKsPMwneMnIYTX7SbJwF+WNV
4S8SZ8db75aPCXjTJGxitYZckW1FytrNZtXgWfhNWoVgs8iB60tJwHKTTgd2/ljw
djznoQR4KstHyV2OvMg6f0EoYI6V8wTOUDA3pMqjEAJkAL/odWWuDrmMiLE6nql6
VQeAMDIlNPQdef31HBVbGg2i6IWUFFo1XAxihssUAAOy77XzJ8GCs8Smfc5dV7Nk
Icgyaz6QrrGNC6Ctp7w3mw3WxNv5pK3VaNSE/DPVc2ingSUrt4IBRXnDNw==
-----END CERTIFICATE-----`;

export const ECDSA_CSR_PEM = `-----BEGIN CERTIFICATE REQUEST-----
MIIBVTCB+wIBADBbMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEZ
MBcGA1UECgwQQ2lwaGVyIFdvcmtiZW5jaDEcMBoGA1UEAwwTYXBpLndvcmtiZW5j
aC5sb2NhbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLuM5FXrTsh6SieIWr6W
SyysT05sjCBmW2z6Q+bv/DQReLudtVlYnbCJ3onsa0RjDMRe6oF4uLdHyxr1t9Uh
QEqgPjA8BgkqhkiG9w0BCQ4xLzAtMB4GA1UdEQQXMBWCE2FwaS53b3JrYmVuY2gu
bG9jYWwwCwYDVR0PBAQDAgeAMAoGCCqGSM49BAMCA0kAMEYCIQC5wYmRy1VSndGx
K8AykkekOvuyreb7pRRawOqyh2BFQAIhAK0eXQtw2OFUdOg2wrhx9BjtPTmvF1VV
4xAmp97nP56/
-----END CERTIFICATE REQUEST-----`;

export const CA_CERTIFICATE_PEM = `-----BEGIN CERTIFICATE-----
MIIDfzCCAmegAwIBAgIUGy14/IgV4fk4x9lhwkBn4q4ZVV4wDQYJKoZIhvcNAQEL
BQAwRzELMAkGA1UEBhMCVVMxHDAaBgNVBAoME0NpcGhlciBXb3JrYmVuY2ggQ0Ex
GjAYBgNVBAMMEVdvcmtiZW5jaCBSb290IENBMB4XDTI2MDkyMTIwMzMxOVoXDTM2
MDkxODIwMzMxOVowRzELMAkGA1UEBhMCVVMxHDAaBgNVBAoME0NpcGhlciBXb3Jr
YmVuY2ggQ0ExGjAYBgNVBAMMEVdvcmtiZW5jaCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjTYTa357Do1NefL7ywNeZM+FmDmV7Zh8eZE4
gDganBEYNtLLWnqZvc2nQmixIHPV324DWRaHksv8sYnkf/nWsBapjWjJrjBPIGvm
0Y9hQNecVHuLLUfh9L0PeEFr4UABemQFW3fHFoWaepGbpcYQ0xeqqMitHMnvuIB+
GyEw6EifLaAk19PTIFi7H34r0Of9Od4w0PNY+Bw4eFBg72HnbBZ+NfJU6XLReE7q
qA6xhu2ecqfpd+yLtnmEBl8ZbHGbrcVBm9od5lVnNGWe+RVukhzOuwPYAY5LIfUx
+2trsCBQc8mePilYUBwyJ6cix1K6t35WndRmFpRkCnW9ONq7awIDAQABo2MwYTAd
BgNVHQ4EFgQUwX6iZPAFT+mPPnEubg1h97KUdf0wHwYDVR0jBBgwFoAUwX6iZPAF
T+mPPnEubg1h97KUdf0wEgYDVR0TAQH/BAgwBgEB/wIBATALBgNVHQ8EBAMCAQYw
DQYJKoZIhvcNAQELBQADggEBAF9bf6nleeHld3q6jy9dOOKYYktj5dJEAENFb4CX
hYTtDmDuxQIyY+uG7DiSx+V/RLLK8p8FMIArwvpr5ER4WTvD9+IrOc/LZmn5g/6A
HUbWz+CFZ80p7n+Yo9LjrHLJbQ+m8rFPJD/KbIzQkbpF93750DJm1GRQR5+wEwxt
x3VuEqqAkeoiXQMSCXrYPRURm05yIJH73XBybruMKe/hHtPpXA/voYullEGDQH0s
+3sL4dq9OBu5mXPJdhcmL9ghvtjrk1Mt3blw3ZDf/tpel38JTIPE36MSrheanXH4
8eoAD34EJH8GeWmfjKeF/QHsILulycerco40XAlg05cGnrs=
-----END CERTIFICATE-----`;

export const CERTIFICATE_CHAIN_PEM = `${RSA_CERTIFICATE_PEM}\n\n${CA_CERTIFICATE_PEM}`;

export function samplesFor(toolId: string): ToolSample[] {
  switch (toolId) {
    case "x509":
      return [
        {
          id: "rsa-tls",
          label: "TLS Server Certificate",
          note: "RSA 2048-bit certificate with SANs and key usage",
          text: RSA_CERTIFICATE_PEM,
        },
        {
          id: "root-ca",
          label: "Root Certificate Authority",
          note: "Self-signed CA certificate with BasicConstraints CA:TRUE",
          text: CA_CERTIFICATE_PEM,
        },
      ];
    case "csr":
      return [
        {
          id: "ec-csr",
          label: "ECDSA P-256 CSR",
          note: "PKCS#10 Certificate Signing Request with requested SANs",
          text: ECDSA_CSR_PEM,
        },
      ];
    case "cert-converter":
      return [
        {
          id: "tls-cert",
          label: "TLS Certificate (PEM)",
          note: "Single PEM certificate to convert to DER or extract public key",
          text: RSA_CERTIFICATE_PEM,
        },
        {
          id: "cert-chain",
          label: "Certificate Chain Bundle",
          note: "Multi-certificate bundle to split into individual certificates",
          text: CERTIFICATE_CHAIN_PEM,
        },
        {
          id: "csr-sample",
          label: "CSR (PKCS#10)",
          note: "Certificate signing request to convert",
          text: ECDSA_CSR_PEM,
        },
      ];
    default:
      return [];
  }
}
