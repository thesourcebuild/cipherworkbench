<#
.SYNOPSIS
    Single (Self-Signed) Certificate Management & Verification
.DESCRIPTION
    Inspect, verify, test, or trust the self-signed certificate on Windows.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("run", "verify", "info", "key", "server", "client", "test-tls", "trust", "help")]
    [string]$Action = "verify",

    [Parameter(Position = 1)]
    [ValidateSet("auto", "1.1", "1.2", "1.3", "all")]
    [string]$TlsVersion = "auto"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

switch ($Action) {
    "run" {
        Write-Host "=== Generating Self-Signed Certificate via TypeScript Engine ===" -ForegroundColor Cyan
        npx tsx .\run.ts
    }
    "verify" {
        Write-Host "=== Verifying Certificate with OpenSSL ===" -ForegroundColor Cyan
        & openssl x509 -in ".\certificate.crt" -text -noout
    }
    "info" {
        Write-Host "=== Inspecting Certificate Subject & SANs ===" -ForegroundColor Cyan
        & openssl x509 -in ".\certificate.crt" -noout -subject -issuer -dates -ext subjectAltName,basicConstraints,keyUsage
    }
    "key" {
        Write-Host "=== Validating Private Key Parameters ===" -ForegroundColor Cyan
        & openssl pkey -in ".\private.key" -text -noout
    }
    "server" {
        Write-Host "=== Starting HTTPS Server on port 8443 (TLS Version: $TlsVersion) ===" -ForegroundColor Cyan
        python .\server.py --tls-version $TlsVersion
    }
    "client" {
        Write-Host "=== Connecting Client to Server (TLS Version: $TlsVersion) ===" -ForegroundColor Cyan
        python .\client.py --tls-version $TlsVersion
    }
    "test-tls" {
        Write-Host "=== Verifying TLS 1.3, TLS 1.2, and TLS 1.1 Support via OpenSSL ===" -ForegroundColor Cyan
        npx tsx -e "
import { testTlsProtocolMatrix } from '../tls_test_harness.ts';
testTlsProtocolMatrix({ basePort: 9551, cert: './certificate.crt', key: './private.key', ca: './certificate.crt' }).then(res => {
  for (const r of res) console.log('  ✓ ' + r.version.toUpperCase() + ': ' + r.protocol + ' | ' + r.cipher + ' | ' + (r.verified ? 'OK' : 'FAIL'));
});
"
    }
    "trust" {
        Write-Host "=== Importing Certificate to Windows 'Trusted People' Store ===" -ForegroundColor Cyan
        Write-Host "Note: Leaf certificates (CA:FALSE) must be imported into TrustedPeople, not Root." -ForegroundColor Yellow
        Import-Certificate -FilePath ".\certificate.crt" -CertStoreLocation Cert:\CurrentUser\TrustedPeople
        Write-Host "[SUCCESS] Imported certificate.crt to Cert:\CurrentUser\TrustedPeople!" -ForegroundColor Green
    }
    "help" {
        Write-Host "Usage: .\commands.ps1 [run | verify | info | key | server | client | trust]"
    }
}
