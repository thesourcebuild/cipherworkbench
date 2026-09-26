<#
.SYNOPSIS
    Single (CA-Signed) Certificate Management & Verification
.DESCRIPTION
    Verify, test, or trust the Root CA and CA-signed server certificate on Windows.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("run", "verify", "info", "server", "client", "test-tls", "trust", "help")]
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
        Write-Host "=== Generating CA and CA-Signed Certificate ===" -ForegroundColor Cyan
        npx tsx .\run.ts
    }
    "verify" {
        Write-Host "=== Verifying Server Certificate Chain against Root CA ===" -ForegroundColor Cyan
        & openssl verify -CAfile ".\ca.crt" ".\server.crt"
    }
    "info" {
        Write-Host "=== Inspecting Server Certificate Extensions ===" -ForegroundColor Cyan
        & openssl x509 -in ".\server.crt" -noout -subject -issuer -dates -ext subjectAltName,basicConstraints,keyUsage,authorityKeyIdentifier
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
testTlsProtocolMatrix({ basePort: 9554, cert: './server.crt', key: './server.key', ca: './ca.crt' }).then(res => {
  for (const r of res) console.log('  ✓ ' + r.version.toUpperCase() + ': ' + r.protocol + ' | ' + r.cipher + ' | ' + (r.verified ? 'OK' : 'FAIL'));
});
"
    }
    "trust" {
        Write-Host "=== Importing Root CA to Windows 'Trusted Root Certification Authorities' ===" -ForegroundColor Cyan
        Import-Certificate -FilePath ".\ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
        Write-Host "[SUCCESS] Imported ca.crt to Cert:\LocalMachine\Root! All browsers now trust server.crt." -ForegroundColor Green
    }
    "help" {
        Write-Host "Usage: .\commands.ps1 [run | verify | info | server | client | test-tls | trust] [auto | 1.1 | 1.2 | 1.3 | all]"
    }
}
